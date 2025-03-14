//  PACKAGES.rs
//    by Lut99
//
//  Created:
//    17 Oct 2022, 15:18:32
//  Last edited:
//    08 Feb 2024, 16:16:22
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines things that relate to packages.
//

use std::borrow::Cow;
use std::convert::{TryFrom, TryInto};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use async_compression::tokio::bufread::GzipDecoder;
use brane_cfg::info::Info as _;
use brane_cfg::node::{CentralConfig, NodeConfig, NodeKind};
use bytes::Buf;
use log::{debug, error, info, warn};
use rand::Rng;
use rand::distr::Alphanumeric;
use scylla::macros::{FromUserType, IntoUserType};
use scylla::{SerializeCql, Session};
use specifications::package::PackageInfo;
use specifications::version::Version;
// use tar::Archive;
use tempfile::TempDir;
use tokio::fs as tfs;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio_stream::StreamExt;
use tokio_tar::{Archive, Entries, Entry};
use uuid::Uuid;
use warp::http::{HeaderValue, StatusCode};
use warp::hyper::Body;
use warp::hyper::body::{Bytes, Sender};
use warp::reply::Response;
use warp::{Rejection, Reply};

pub use crate::errors::PackageError as Error;
use crate::spec::Context;


/***** HELPER MACROS *****/
/// Macro that early quits from a warp function by printing the error and then returning a 500.
macro_rules! fail {
    ($err:expr) => {{
        // Implement a phony type that does implement reject (whatever)
        struct InternalError;
        impl std::fmt::Debug for InternalError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "An internal error has occurred.") }
        }
        impl warp::reject::Reject for InternalError {}

        // Now write the error to stderr and the internal error to the client
        let err = $err;
        error!("{}", err);
        return Err(warp::reject::custom(InternalError));
    }};

    ($path:ident, $err:expr) => {{
        // In this overload, we attempt to clear the existing file first
        let path = &$path;
        if path.is_file() {
            if let Err(err) = tfs::remove_file(&path).await {
                warn!("Failed to remove temporary download result '{}': {}", path.display(), err);
            }
        } else if path.is_dir() {
            if let Err(err) = tfs::remove_dir_all(&path).await {
                warn!("Failed to remove temporary download results '{}': {}", path.display(), err);
            }
        }

        // Move to the normal overload for the rest
        fail!($err)
    }};
}





/***** AUXILLARY STRUCTS *****/
/// Defines the contents of a single Scylla database row that describes a package.
#[derive(Clone, IntoUserType, FromUserType, SerializeCql)]
pub struct PackageUdt {
    pub created: i64,
    pub description: String,
    pub detached: bool,
    pub digest: String,
    pub functions_as_json: String,
    pub id: Uuid,
    pub kind: String,
    pub name: String,
    pub owners: Vec<String>,
    pub types_as_json: String,
    pub version: String,
}

impl TryFrom<PackageInfo> for PackageUdt {
    type Error = Error;

    fn try_from(package: PackageInfo) -> Result<Self, Self::Error> {
        // First, serialize the functions and the types as JSON
        let functions_as_json: String = match serde_json::to_string(&package.functions) {
            Ok(funcs) => funcs,
            Err(err) => {
                return Err(Error::FunctionsSerializeError { name: package.name, err });
            },
        };
        let types_as_json: String = match serde_json::to_string(&package.types) {
            Ok(types) => types,
            Err(err) => {
                return Err(Error::TypesSerializeError { name: package.name, err });
            },
        };

        // Assert that there is a digest
        let digest: String = match package.digest {
            Some(digest) => digest,
            None => {
                return Err(Error::MissingDigest { name: package.name });
            },
        };

        // We can then simply populate the package info
        Ok(Self {
            created: package.created.timestamp_millis(),
            description: package.description,
            detached: package.detached,
            digest,
            functions_as_json,
            id: package.id,
            kind: String::from(package.kind),
            name: package.name,
            owners: package.owners,
            types_as_json,
            version: package.version.to_string(),
        })
    }
}





/***** AUXILLARY FUNCTIONS *****/
/// Ensures that the packages table is present in the given Scylla database.
///
/// # Arguments
/// - `scylla`: The Scylla database session that allows us to talk to it.
///
/// # Returns
/// Nothing, but does change the target Scylla database to include the new table if it didn't already.
///
/// # Errors
/// This function errors if the communication with the given database failed too.
pub async fn ensure_db_table(scylla: &Session) -> Result<(), Error> {
    // Define the `brane.package` type
    if let Err(err) = scylla
        .query(
            "CREATE TYPE IF NOT EXISTS brane.package (
                created bigint
            , description text
            , detached boolean
            , digest text
            , functions_as_json text
            , id uuid
            , kind text
            , name text
            , owners list<text>
            , types_as_json text
            , version text
        )",
            &[],
        )
        .await
    {
        return Err(Error::PackageTypeDefineError { err });
    }

    // Define  the `brane.packages` table
    if let Err(err) = scylla
        .query(
            "CREATE TABLE IF NOT EXISTS brane.packages (
              name text
            , version text
            , file text
            , package frozen<package>
            , PRIMARY KEY (name, version)
        )",
            &[],
        )
        .await
    {
        return Err(Error::PackageTableDefineError { err });
    }

    // Done
    Ok(())
}



/// Inserts the given package into the given Scylla database.
///
/// # Arguments
/// - `scylla`: The Scylla database session that allows us to talk to it.
/// - `package`: The PackageInfo struct that describes the package, and is what we will insert. Note, however, that not _all_ information will make it; only the info present in a `PackageUdt` struct will.
/// - `path`: The Path where the container image may be found.
///
/// # Returusn
/// Nothing, but does change the target Scylla database to include the new package.
///
/// # Errors
/// This function errors if the communication with the given database failed too or if the given PackageInfo could not be converted to a PackageUdt for some reason.
async fn insert_package_into_db(scylla: &Arc<Session>, package: &PackageInfo, path: impl AsRef<Path>) -> Result<(), Error> {
    let path: &Path = path.as_ref();

    // Attempt to convert the package
    let package: PackageUdt = package.clone().try_into()?;

    // Insert it
    if let Err(err) = scylla
        .query(
            "INSERT INTO brane.packages (
              name
            , version
            , file
            , package
        ) VALUES(?, ?, ?, ?)
        ",
            (&package.name, &package.version, path.to_string_lossy().to_string(), &package),
        )
        .await
    {
        return Err(Error::PackageInsertError { name: package.name, err });
    }

    // Done
    Ok(())
}





/***** LIBRARY *****/
/// Downloads a file from the `brane-api` "registry" to the client.
///
/// # Arguments
/// - `name`: The name of the package (container) to download.
/// - `version`: The version of the package (container) to download. May be 'latest'.
/// - `context`: The Context that describes some properties of the running environment, such as the location where the container images are stored.
///
/// # Returns
/// A reply with as body the container archive. This archive will likely not be compressed (for now).
///
/// # Errors
/// This function errors if resolving a 'latest' version failed, the requested package/version pair did not exist, the Scylla database was unreachable or we failed to read the image file.
pub async fn download(name: String, version: String, context: Context) -> Result<impl Reply, Rejection> {
    info!("Handling GET on '/packages/{}/{}' (i.e., pull package)", name, version);

    // Attempt to resolve the version from the Scylla database in the context
    debug!("Resolving version '{}'...", version);
    let version: Version = if version.to_lowercase() == "latest" {
        let versions = match context.scylla.query("SELECT version FROM brane.packages WHERE name=?", vec![&name]).await {
            Ok(versions) => versions,
            Err(err) => {
                fail!(Error::VersionsQueryError { name, err });
            },
        };
        let mut latest: Option<Version> = None;
        if let Some(rows) = versions.rows {
            for row in rows {
                // Get the string value
                let version: &str = row.columns[0].as_ref().unwrap().as_text().unwrap();

                // Attempt to parse
                let version: Version = match Version::from_str(version) {
                    Ok(version) => version,
                    Err(err) => {
                        fail!(Error::VersionParseError { raw: version.into(), err });
                    },
                };

                // Finally, find the most recent one
                if latest.is_none() || version > *latest.as_ref().unwrap() {
                    latest = Some(version);
                }
            }
        }

        // Error if none was found
        match latest {
            Some(version) => version,
            None => {
                error!("{}", Error::NoVersionsFound { name });
                return Err(warp::reject::not_found());
            },
        }
    } else {
        match Version::from_str(&version) {
            Ok(version) => version,
            Err(err) => {
                fail!(Error::VersionParseError { raw: version, err });
            },
        }
    };

    // With the version resolved, query the filename
    debug!("Retrieving filename for package '{}'@{}", name, version);
    let file: PathBuf =
        match context.scylla.query("SELECT file FROM brane.packages WHERE name=? AND version=?", vec![&name, &version.to_string()]).await {
            Ok(file) => {
                if let Some(rows) = file.rows {
                    if rows.is_empty() {
                        error!("{}", Error::UnknownPackage { name, version });
                        return Err(warp::reject::not_found());
                    }
                    if rows.len() > 1 {
                        panic!("Database contains {} entries with the same name & version ('{}' & '{}')", rows.len(), name, version);
                    }
                    rows[0].columns[0].as_ref().unwrap().as_text().unwrap().into()
                } else {
                    error!("{}", Error::UnknownPackage { name, version });
                    return Err(warp::reject::not_found());
                }
            },
            Err(err) => {
                fail!(Error::PathQueryError { name, version, err });
            },
        };

    // Retrieve the size of the file for the content length
    let length: u64 = match tfs::metadata(&file).await {
        Ok(metadata) => metadata.len(),
        Err(err) => {
            fail!(Error::FileMetadataError { path: file, err });
        },
    };

    // Open a stream to said file
    debug!("Sending back reply with compressed archive...");
    let (mut body_sender, body): (Sender, Body) = Body::channel();

    // Spawn a tokio task that handles the rest while we return the response header
    tokio::spawn(async move {
        // Open the archive file to read
        let mut handle: tfs::File = match tfs::File::open(&file).await {
            Ok(handle) => handle,
            Err(err) => {
                fail!(Error::FileOpenError { path: file, err });
            },
        };

        // Read it chunk-by-chunk
        // (The size of the buffer, like most of the code but edited for not that library cuz it crashes during compilation, has been pulled from https://docs.rs/stream-body/latest/stream_body/)
        let mut buf: [u8; 1024 * 16] = [0; 1024 * 16];
        loop {
            // Read the chunk
            let bytes: usize = match handle.read(&mut buf).await {
                Ok(bytes) => bytes,
                Err(err) => {
                    fail!(Error::FileReadError { path: file, err });
                },
            };
            if bytes == 0 {
                break;
            }

            // Send that with the body
            if let Err(err) = body_sender.send_data(Bytes::copy_from_slice(&buf[..bytes])).await {
                fail!(Error::FileSendError { path: file, err });
            }
        }

        // Done
        Ok(())
    });

    // Done (at least, this task is)
    let mut response: Response = Response::new(body);
    response.headers_mut().insert("Content-Disposition", HeaderValue::from_static("attachment; filename=image.tar"));
    response.headers_mut().insert("Content-Length", HeaderValue::from(length));
    Ok(response)
}

/// Uploads a new package (container) to the central registry.
///
/// # Arguments
/// - `package_archive`: The Bytes of the package archive to store somewhere.
/// - `context`: The Context that stores properties about the environment, such as the directory where we store the container files.
///
/// # Returns
/// The Warp reply that contains the status code of the thing (e.g., OK if everything went fine).
///
/// # Errors
/// This function errors if we fail to either write the package info to the Scylla database or the package archive to the local filesystem.
pub async fn upload<S, B>(package_archive: S, context: Context) -> Result<impl Reply, Rejection>
where
    S: StreamExt<Item = Result<B, warp::Error>> + Unpin,
    B: Buf,
{
    info!("Handling POST on '/packages' (i.e., upload new package)");
    let mut package_archive = package_archive;



    /* Step 0: Load config files */
    // Load the node config file
    let node_config: NodeConfig = match NodeConfig::from_path(&context.node_config_path) {
        Ok(config) => config,
        Err(err) => {
            fail!(Error::NodeConfigLoadError { err });
        },
    };
    let central: &CentralConfig = match node_config.node.try_central() {
        Some(central) => central,
        None => {
            fail!(Error::NodeConfigUnexpectedKind {
                path:     context.node_config_path,
                got:      node_config.node.kind(),
                expected: NodeKind::Central,
            });
        },
    };



    /* Step 1: Write the _uploadable_ archive */
    // Open a temporary directory
    debug!("Preparing filesystem...");
    let tempdir: TempDir = match TempDir::new() {
        Ok(tempdir) => tempdir,
        Err(err) => {
            fail!(Error::TempDirCreateError { err });
        },
    };
    let tempdir_path: &Path = tempdir.path();

    // Generate a unique ID for the image name.
    let id: String = rand::rng().sample_iter(&Alphanumeric).take(8).map(char::from).collect();

    // Attempt to open a new file
    let tar_path: PathBuf = tempdir_path.join(format!("{id}.tar.gz"));
    let mut handle = match tfs::File::create(&tar_path).await {
        Ok(handle) => handle,
        Err(err) => {
            fail!(Error::TarCreateError { path: tar_path, err });
        },
    };

    // Start writing the stream to it
    debug!("Downloading submitted archive to '{}'...", tar_path.display());
    while let Some(chunk) = package_archive.next().await {
        // Unwrap the chunk
        let mut chunk: B = match chunk {
            Ok(chunk) => chunk,
            Err(err) => {
                fail!(Error::BodyReadError { err });
            },
        };

        // Write the chunk to the Tokio file
        if let Err(err) = handle.write_all_buf(&mut chunk).await {
            fail!(Error::TarWriteError { path: tar_path, err });
        }
    }

    // Wait until the handle is finished writing
    if let Err(err) = handle.shutdown().await {
        fail!(Error::TarFlushError { path: tar_path, err });
    }



    /* Step 2: Extract the archive into a package info and container image. */
    // Re-open the file
    debug!("Extracting submitted archive file...");
    let info_path: PathBuf = tempdir_path.join("package.yml");
    let image_path: PathBuf = central.paths.packages.join(format!("{id}.tar"));
    {
        let handle: tfs::File = match tfs::File::open(&tar_path).await {
            Ok(handle) => handle,
            Err(err) => {
                fail!(Error::TarReopenError { path: tar_path, err });
            },
        };

        // Wrap it in the unarchiver & decompressor
        let dec: GzipDecoder<BufReader<tfs::File>> = GzipDecoder::new(BufReader::new(handle));
        let mut tar: Archive<GzipDecoder<_>> = Archive::new(dec);

        // Iterate over the entries in the stream
        let mut entries: Entries<_> = match tar.entries() {
            Ok(entries) => entries,
            Err(err) => {
                fail!(Error::TarEntriesError { path: tar_path, err });
            },
        };
        let mut i: usize = 0;
        let mut did_info: bool = false;
        let mut did_image: bool = false;
        while let Some(entry) = entries.next().await {
            // Unwrap the entry
            let mut entry: Entry<_> = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    fail!(Error::TarEntryError { path: tar_path, entry: i, err });
                },
            };

            // Attempt to get its path
            let entry_path: Cow<Path> = match entry.path() {
                Ok(path) => path,
                Err(err) => {
                    fail!(Error::TarEntryPathError { path: tar_path, entry: i, err });
                },
            };

            // Attempt to extract it based on the type of file
            if entry_path == PathBuf::from("package.yml") {
                // Extract as such
                debug!("Extracting '{}/package.yml' to '{}'...", tar_path.display(), info_path.display());
                if let Err(err) = entry.unpack(&info_path).await {
                    fail!(Error::TarFileUnpackError { file: PathBuf::from("package.yml"), tarball: tar_path, target: info_path, err });
                }
                did_info = true;
            } else if entry_path == PathBuf::from("image.tar") {
                // Extract as such
                debug!("Extracting '{}/image.tar' to '{}'...", tar_path.display(), image_path.display());
                if let Err(err) = entry.unpack(&image_path).await {
                    fail!(Error::TarFileUnpackError { file: PathBuf::from("image.tar"), tarball: tar_path, target: image_path, err });
                }
                did_image = true;
            } else {
                debug!("Ignoring irrelevant entry '{}' in '{}'", entry_path.display(), tar_path.display());
            }

            // Advance the index for debugging purposes
            i += 1;
        }

        // Assert that both of our relevant files must have been present
        if !did_info || !did_image {
            fail!(Error::TarMissingEntries { expected: vec!["package.yml", "image.tar"], path: tar_path });
        }
    }



    /* Step 3: Insert the package into the DB */
    debug!("Reading package info '{}'...", info_path.display());
    // Read the extracted package info
    let sinfo: String = match tfs::read_to_string(&info_path).await {
        Ok(sinfo) => sinfo,
        Err(err) => {
            fail!(Error::PackageInfoReadError { path: info_path, err });
        },
    };
    let info: PackageInfo = match serde_yaml::from_str(&sinfo) {
        Ok(info) => info,
        Err(err) => {
            fail!(Error::PackageInfoParseError { path: info_path, err });
        },
    };

    // Copy the image tar to the proper location
    let result_path: PathBuf = central.paths.packages.join(format!("{}-{}.tar", info.name, info.version));
    debug!("Moving image '{}' to '{}'...", image_path.display(), result_path.display());
    if let Err(err) = tfs::rename(&image_path, &result_path).await {
        fail!(image_path, Error::FileMoveError { from: image_path, to: result_path, err });
    }

    // Call the insert function to store the dataset in the registry
    debug!("Inserting package '{}' (version {}) into Scylla DB...", info.name, info.version);
    if let Err(err) = insert_package_into_db(&context.scylla, &info, &result_path).await {
        fail!(result_path, err);
    }



    /* Step 4: Done */
    // The package has now been added
    debug!("Upload of package '{}' (version {}) complete.", info.name, info.version);
    Ok(StatusCode::OK)

    // Note that the temporary directory is automagically removed
}
