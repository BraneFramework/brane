//  EFLINT JSON.rs
//    by Lut99
//
//  Created:
//    19 Oct 2024, 10:21:59
//  Last edited:
//    02 May 2025, 09:27:19
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a compiler from a [`Workflow`] to a series of eFLINT phrases.
//

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::fmt::{Display, Formatter, Result as FResult};

use policy_reasoner::workflow::visitor::Visitor;
use policy_reasoner::workflow::{Dataset, Elem, ElemBranch, ElemCall, ElemLoop, ElemParallel, Entity, Metadata, Workflow};
use rand::Rng as _;
use rand::distr::Alphanumeric;
use tracing::{trace, warn};

use super::compile::COMMIT_CALL_NAME;
use crate::workflow::compile::TOPLEVEL_RETURN_CALL_NAME;


/***** HELPER MACROS *****/
/// Shorthand for creating an eFLINT JSON Specification true postulation.
macro_rules! create {
    ($inst:expr) => {
        format!("+{}.\n", $inst)
    };
}

/// Shorthand for creating an eFLINT JSON Specification constructor application.
macro_rules! constr_app {
    ($id:expr $(, $args:expr)* $(,)?) => {
        {
            let mut res = $id.to_string();
            res.push('(');
            let mut first = true;
            $(#[allow(unused)] if !first { res.push_str(", ") } else { first = false }
              res.push_str(&$args.to_string());)*
            res.push(')');
            res
        }
    };
}

/// Shorthand for creating an eFLINT JSON Specification string literal.
macro_rules! str_lit {
    ($val:expr) => {
        format!("{:?}", $val)
    };
}





/***** HELPER FUNCTIONS *****/
/// Compiles a given piece of metadata.
///
/// # Arguments
/// - `metadata`: The [`Metadata`] to compile.
/// - `phrases`: The buffer to compile to.
fn compile_metadata(metadata: &Metadata, phrases: &mut Vec<String>) {
    // First, we push the tag
    // ```eflint
    // +tag(#metadata.tag).
    // ```
    let tag: String = constr_app!("tag", str_lit!(metadata.tag.clone()));
    phrases.push(create!(tag.clone()));

    // Push the signature
    let signature: String = if let Some((owner, signature)) = &metadata.signature {
        // ```eflint
        // +signature(user(#owner), #signature).
        // ```
        constr_app!("signature", constr_app!("user", str_lit!(owner.id.clone())), str_lit!(signature.clone()))
    } else {
        // Push an empty signature, to be sure that the one is in serialized metadata is still findable
        // ```eflint
        // +signature(user(""), "").
        // ```
        constr_app!("signature", constr_app!("user", str_lit!("")), str_lit!(""))
    };
    phrases.push(create!(signature.clone()));

    // Then push the metadata as a whole
    phrases.push(create!(constr_app!("metadata", tag, signature)));
}





/***** FORMATTERS *****/
/// Serializes a workflow to eFLINT using it's [`Display`]-implementation.
pub struct WorkflowToEflint<'w>(pub &'w Workflow);
impl Display for WorkflowToEflint<'_> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { eflint_fmt(self.0, f) }
}





/***** VISITORS *****/
/// Names all loops in a [`Workflow`].
struct LoopNamer<'w> {
    /// The identifier of the workflow.
    wf_id: &'w str,
    /// Stores the names of the loops.
    loops: HashMap<*const ElemLoop, String>,
}
impl<'w> LoopNamer<'w> {
    /// Constructor for the LoopNamer.
    ///
    /// # Arguments
    /// - `wf_id`: The identifier of the workflow we're considering.
    ///
    /// # Returns
    /// A new LoopNamer, ready for naming.
    #[inline]
    pub fn new(wf_id: &'w str) -> Self { Self { wf_id, loops: HashMap::new() } }
}
impl<'w> Visitor<'w> for LoopNamer<'w> {
    type Error = Infallible;

    fn visit_loop(&mut self, elem: &'w ElemLoop) -> Result<Option<&'w Elem>, Self::Error> {
        let ElemLoop { body, next } = elem;

        // Generate a name for this loop
        self.loops.insert(
            elem as *const ElemLoop,
            format!("{}-{}-loop", self.wf_id, rand::rng().sample_iter(Alphanumeric).take(4).map(char::from).collect::<String>()),
        );

        // Continue
        self.visit(body)?;
        Ok(Some(next))
    }
}

/// Finds the flows of datasets through a sequence of elements as if it was a single element.
struct DataAnalyzer<'w> {
    /// The names of loops we've already found.
    names: &'w HashMap<*const ElemLoop, String>,
    /// The first nodes that we encounter with their (potential) inputs.
    ///
    /// There can be more than one if a branch or parallel is found.
    first: Vec<(String, HashSet<Dataset>)>,
    /// The (potential) outputs of this chain of elements.
    last:  HashSet<Dataset>,
}
impl<'w> DataAnalyzer<'w> {
    /// Constructor for the DataAnalyzer.
    ///
    /// # Arguments
    /// - `names`: A list of names for loops.
    ///
    /// # Returns
    /// A new DataAnalyzer struct, ready to analyze.
    #[inline]
    pub fn new(names: &'w HashMap<*const ElemLoop, String>) -> Self { Self { names, first: Vec::new(), last: HashSet::new() } }
}
impl<'w> Visitor<'w> for DataAnalyzer<'w> {
    type Error = Infallible;

    fn visit_call(&mut self, elem: &'w ElemCall) -> Result<Option<&'w Elem>, Self::Error> {
        // Log it's the first if we haven't found any yet
        if self.first.is_empty() {
            self.first.push((elem.id.clone(), elem.input.iter().cloned().collect()));
        }
        self.last.clear();
        self.last.extend(elem.output.iter().cloned());

        // Continue
        Ok(Some(&elem.next))
    }

    fn visit_branch(&mut self, elem: &'w ElemBranch) -> Result<Option<&'w Elem>, Self::Error> {
        // Aggregate the inputs & outputs of the branches
        let add_firsts: bool = !self.first.is_empty();
        self.last.clear();
        for branch in &elem.branches {
            let mut analyzer = Self::new(self.names);
            analyzer.visit(branch)?;
            if add_firsts {
                self.first.extend(analyzer.first);
            }
            self.last.extend(analyzer.last);
        }

        // OK, continue with the branch's next
        Ok(Some(&elem.next))
    }

    fn visit_parallel(&mut self, elem: &'w ElemParallel) -> Result<Option<&'w Elem>, Self::Error> {
        // Aggregate the inputs & outputs of the branches
        let add_firsts: bool = !self.first.is_empty();
        self.last.clear();
        for branch in &elem.branches {
            let mut analyzer = Self::new(self.names);
            analyzer.visit(branch)?;
            if add_firsts {
                self.first.extend(analyzer.first);
            }
            self.last.extend(analyzer.last);
        }

        // OK, continue with the branch's next
        Ok(Some(&elem.next))
    }

    fn visit_loop(&mut self, elem: &'w ElemLoop) -> Result<Option<&'w Elem>, Self::Error> {
        // We recurse to find the inputs- and outputs
        let mut analyzer = Self::new(self.names);
        analyzer.visit(&elem.body)?;

        // Propagate these
        if self.first.is_empty() {
            // Get the loop's name
            let id: &String = self.names.get(&(elem as *const ElemLoop)).unwrap_or_else(|| panic!("Encountered loop without name after loop naming"));

            // Set this loop as the first node, combining all the input dataset from the children
            self.first.push((id.clone(), analyzer.first.into_iter().flat_map(|(_, data)| data).collect()));
        }
        self.last.clear();
        self.last.extend(analyzer.last);

        // Continue with iteration
        Ok(Some(&elem.next))
    }
}

/// Compiles the calls & loops in the given sequence to eFLINT phrases.
struct EFlintCompiler<'w> {
    /// The identifier of the workflow.
    wf_id:   &'w str,
    /// The end user of the workflow.
    wf_user: &'w Option<Entity>,
    /// The names of loops we've already found.
    names:   &'w HashMap<*const ElemLoop, String>,
    /// The phrases we're compiling to.
    phrases: Vec<String>,
}
impl<'w> EFlintCompiler<'w> {
    /// Constructor for the EFlintCompiler.
    ///
    /// # Arguments
    /// - `wf_id`: The identifier of the workflow we're considering.
    /// - `wf_user`: The end user of the workflow we're considering.
    /// - `names`: A list of names for loops.
    ///
    /// # Returns
    /// A new EFlintCompiler struct, ready to compile.
    #[inline]
    pub fn new(wf_id: &'w str, wf_user: &'w Option<Entity>, names: &'w HashMap<*const ElemLoop, String>) -> Self {
        Self { wf_id, wf_user, names, phrases: Vec::new() }
    }
}
impl<'w> Visitor<'w> for EFlintCompiler<'w> {
    type Error = Infallible;

    #[inline]
    fn visit_call(&mut self, elem: &'w ElemCall) -> Result<Option<&'w Elem>, Self::Error> {
        trace!("Compiling Elem::Call to eFLINT");

        // Define a new task call and make it part of the workflow
        // ```eflint
        // +node(workflow(#wf_id), #id).
        // +task(node(workflow(#wf_id), #id)).
        // ```
        let node: String = constr_app!("node", constr_app!("workflow", str_lit!(self.wf_id)), str_lit!(elem.id.clone()));
        self.phrases.push(create!(node.clone()));
        if elem.task == COMMIT_CALL_NAME {
            self.phrases.push(create!(constr_app!("commit", node.clone())));
        } else if elem.task == TOPLEVEL_RETURN_CALL_NAME {
            if let Some(wf_user) = self.wf_user {
                // Mark the results as results of the workflow
                for r in &elem.input {
                    // ```eflint
                    // +workflow-result-recipient(workflow-result(workflow(#wf_id), asset(#r.name)), user(#wf_user.name)).
                    // ```
                    self.phrases.push(create!(constr_app!(
                        "workflow-result-recipient",
                        constr_app!("workflow-result", constr_app!("workflow", str_lit!(self.wf_id)), constr_app!("asset", str_lit!(r.id.clone()))),
                        constr_app!("user", str_lit!(wf_user.id.clone())),
                    )));
                }
            }

            // Continue
            return Ok(Some(&elem.next));
        } else {
            self.phrases.push(create!(constr_app!("task", node.clone())));
        }

        // Link the code input
        // ```eflint
        // +node-input(#node, asset("#package[#version]")).
        // +function(node-input(#node, asset("#package[#version]")), #name).
        // ```
        let (package, function) = elem.task.split_once("::").unwrap_or((&elem.task, &elem.task));
        let code_input: String = constr_app!("node-input", node.clone(), constr_app!("asset", str_lit!(package)));
        self.phrases.push(create!(code_input.clone()));
        self.phrases.push(create!(constr_app!("function", code_input.clone(), str_lit!(function))));

        // Add its inputs
        for i in &elem.input {
            // Link this input to the task
            // ```eflint
            // +node-input(#node, asset(#i.name)).
            // ```
            let node_input: String = constr_app!("node-input", node.clone(), constr_app!("asset", str_lit!(i.id.clone())));
            self.phrases.push(create!(node_input.clone()));

            // Add where this dataset lives if we know that
            if let Some(from) = &i.from {
                // It's planned to be transferred from this location
                // ```eflint
                // +node-input-from(#node-input, domain(user(#from))).
                // ```
                self.phrases.push(create!(constr_app!(
                    "node-input-from",
                    node_input,
                    constr_app!("domain", constr_app!("user", str_lit!(from.id.clone())))
                )));
            } else if let Some(at) = &elem.at {
                // It's present on the task's location
                // ```eflint
                // +node-input-from(#node-input, domain(user(#at))).
                // ```
                self.phrases.push(create!(constr_app!(
                    "node-input-from",
                    node_input,
                    constr_app!("domain", constr_app!("user", str_lit!(at.id.clone())))
                )));
            } else {
                warn!("Encountered input dataset '{}' without transfer source in task '{}' as part of workflow '{}'", i.id, elem.id, self.wf_id);
            }
        }
        // Add the output, if any
        for o in &elem.output {
            // ```eflint
            // +node-output(#node, asset(#o.name)).
            // ```
            self.phrases.push(create!(constr_app!("node-output", node.clone(), constr_app!("asset", str_lit!(o.id.clone())))));
        }
        // Add the location of the task execution
        if let Some(at) = &elem.at {
            // ```eflint
            // +node-at(#node, domain(user(#at))).
            // ```
            self.phrases.push(create!(constr_app!("node-at", node.clone(), constr_app!("domain", constr_app!("user", str_lit!(at.id.clone()))))));
        } else {
            warn!("Encountered unplanned task '{}' part of workflow '{}'", elem.id, self.wf_id);
        }

        // Finally, add any task metadata
        for m in &elem.metadata {
            // Write the metadata's children
            compile_metadata(m, &mut self.phrases);

            // Resolve the metadata's signature
            let (owner, signature): (&str, &str) =
                m.signature.as_ref().map(|(owner, signature)| (owner.id.as_str(), signature.as_str())).unwrap_or(("", ""));

            // Write the phrase
            // ```eflint
            // +node-metadata(#node, metadata(tag(#m.tag), signature(user(#m.assigner), #m.signature)))).
            // ```
            self.phrases.push(create!(constr_app!(
                "node-metadata",
                node.clone(),
                constr_app!(
                    "metadata",
                    constr_app!("tag", str_lit!(m.tag.clone())),
                    constr_app!("signature", constr_app!("user", str_lit!(owner)), str_lit!(signature)),
                )
            )));
        }

        // OK, move to the next
        Ok(Some(&elem.next))
    }

    #[inline]
    fn visit_loop(&mut self, elem: &'w ElemLoop) -> Result<Option<&'w Elem>, Self::Error> {
        // Serialize the body phrases first
        self.visit(&elem.body)?;

        // Serialize the node
        // ```eflint
        // +node(workflow(#wf_id), #id).
        // +loop(node(workflow(#wf_id), #id)).
        // ```
        let id: &String = self.names.get(&(elem as *const ElemLoop)).unwrap_or_else(|| panic!("Found unnamed loop after loop naming"));
        let node: String = constr_app!("node", constr_app!("workflow", str_lit!(self.wf_id)), str_lit!(id.clone()));
        self.phrases.push(create!(node.clone()));
        self.phrases.push(create!(constr_app!("loop", node.clone())));

        // Collect the inputs & outputs of the body
        let mut analyzer = DataAnalyzer::new(self.names);
        analyzer.visit(&elem.body)?;

        // Post-process the input into a list of body nodes and a list of data input
        let (bodies, inputs): (Vec<String>, Vec<HashSet<Dataset>>) = analyzer.first.into_iter().unzip();
        let inputs: HashSet<Dataset> = inputs.into_iter().flatten().collect();

        // Add the loop inputs
        for input in inputs {
            // ```eflint
            // +node-input(#node, asset(#i.name)).
            // ```
            let node_input: String = constr_app!("node-input", node.clone(), constr_app!("asset", str_lit!(input.id.clone())));
            self.phrases.push(create!(node_input.clone()));

            // Add where this dataset lives if we know that
            if let Some(from) = &input.from {
                // It's planned to be transferred from this location
                // ```eflint
                // +node-input-from(#node-input, domain(user(#from))).
                // ```
                self.phrases.push(create!(constr_app!(
                    "node-input-from",
                    node_input,
                    constr_app!("domain", constr_app!("user", str_lit!(from.id.clone())))
                )));
            } else {
                warn!("Encountered input dataset '{}' without transfer source in commit '{}' as part of workflow '{}'", input.id, id, self.wf_id);
            }
        }
        // Add the loop outputs
        for output in analyzer.last {
            // ```eflint
            // +node-output(#node, asset(#output.name)).
            // ```
            self.phrases.push(create!(constr_app!("node-output", node.clone(), constr_app!("asset", str_lit!(output.id.clone())))));
        }
        // Add the loop's bodies
        for body in bodies {
            // ```eflint
            // +loop-body(loop(#node), node(workflow(#wf_id), #body)).
            // ```
            self.phrases.push(create!(constr_app!(
                "loop-body",
                constr_app!("loop", node.clone()),
                constr_app!("node", constr_app!("workflow", str_lit!(self.wf_id)), str_lit!(body))
            )));
        }

        // Done, continue with the next one
        Ok(Some(&elem.next))
    }
}





/***** LIBRARY FUNCTIONS *****/
/// Compiles a [`Workflow`] to a series of eFLINT phrases.
///
/// # Arguments
/// - `wf`: The [`Workflow`] to compile.
/// - `f`: Some [`Formatter`] to write to.
///
/// # Errors
/// This function fails if it fails to write to the given `f`ormatter.
pub fn eflint_fmt(wf: &Workflow, f: &mut Formatter) -> FResult {
    // First, we shall name all loops
    let mut namer = LoopNamer::new(&wf.id);
    namer.visit(&wf.start).unwrap();

    // Start the compiler
    let mut compiler = EFlintCompiler::new(&wf.id, &wf.user, &namer.loops);

    // Kick off the first phrase(s) by adding the notion of the workflow as a whole
    // ```eflint
    // +workflow(#self.id).
    // ```
    let workflow = constr_app!("workflow", str_lit!(wf.id.clone()));
    compiler.phrases.push(create!(workflow.clone()));

    // Add workflow metadata
    for m in &wf.metadata {
        // Write the metadata's children
        compile_metadata(m, &mut compiler.phrases);

        // Resolve the metadata's signature
        let (owner, signature): (&str, &str) =
            m.signature.as_ref().map(|(owner, signature)| (owner.id.as_str(), signature.as_str())).unwrap_or(("", ""));

        // Write the phrase
        // ```eflint
        // +workflow-metadata(#workflow, metadata(tag(#m.tag), signature(user(#m.assigner), #m.signature)))).
        // ```
        compiler.phrases.push(create!(constr_app!(
            "workflow-metadata",
            workflow.clone(),
            constr_app!(
                "metadata",
                constr_app!("tag", str_lit!(m.tag.clone())),
                constr_app!("signature", constr_app!("user", str_lit!(owner)), str_lit!(signature)),
            )
        )));
    }

    // Compile the 'flow to a list of phrases
    compiler.visit(&wf.start).unwrap();

    // Done!
    for phrase in compiler.phrases {
        write!(f, "{phrase}")?;
    }
    Ok(())
}
