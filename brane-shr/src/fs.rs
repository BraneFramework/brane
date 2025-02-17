//  FS.rs
//    by Lut99
//
//  Created:
//    09 Nov 2022, 11:12:06
//  Last edited:
//    13 Dec 2023, 08:19:48
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a few helper functions for filesystem operations.
//

use std::ffi::{OsStr, OsString};
use std::fmt::{Display, Formatter, Result as FResult};
use std::fs::{self, Permissions};
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign};
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use async_compression::tokio::bufread::GzipDecoder;
use async_compression::tokio::write::GzipEncoder;
use console::{Style, style};
use fs2::FileExt as _;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, warn};
use reqwest::{Client, Request, Response, StatusCode, Url};
use sha2::{Digest as _, Sha256};
use specifications::version::Version;
use tokio::fs as tfs;
use tokio::io::{self as tio, AsyncWriteExt};
use tokio_stream::StreamExt;
use tokio_tar::{Archive, Builder, Entries, Entry};

use crate::formatters::Capitalizeable;


/***** TESTS *****/
#[cfg(test)]
pub mod tests {
    use std::fs;
    use std::io::{Read, Write};

    use getrandom::getrandom;
    use tempfile::TempDir;

    use super::*;
    use crate::formatters::{BlockFormatter, HexFormatter};


    /// A test whether we can correct compress, then uncompress an archive as we expected.
    ///
    /// # Arguments
    /// - `extra_dirs`: A path to inject between the temporary folder and the source (to test the correct removal of it in the tar)
    /// - `skip_dir`: Whether to skip the root directory or not (see `archive_async`s documentation).
    ///
    /// # Returns
    /// Nothing, but that means the test succeeded.
    ///
    /// # Panics
    /// This function panics if the test fails, with the reason it fails.
    // #[tokio::test]
    async fn test_archive_unarchive(extra_dirs: PathBuf, skip_dir: bool) {
        /***** PREPARATION *****/
        // Find a temporary folder
        let tempdir: TempDir = match TempDir::new() {
            Ok(tempdir) => tempdir,
            Err(err) => {
                panic!("Failed to create a temporary directory: {}", err);
            },
        };
        let source: PathBuf = tempdir.path().join(extra_dirs).join("src");

        // Create some to-be-compressed files there
        let file1: &'static str = {
            "According to all known laws of aviation, there is no way a bee should be able to fly. Its wings are too small to get its fat little \
             body off the ground. The bee, of course, flies anyway because bees don't care what humans think is impossible. Yellow, black. Yellow, \
             black. Yellow, black. Yellow, black. Ooh, black and yellow! Let's shake it up a little. Barry! Breakfast is ready! Ooming! Hang on a \
             second. Hello? - Barry? - Adam? - Oan you believe this is happening? - I can't. I'll pick you up. Looking sharp. Use the stairs. Your \
             father paid good money for those. Sorry. I'm excited. Here's the graduate. We're very proud of you, son. A perfect report card, all \
             B's. Very proud. Ma! I got a thing going here. - You got lint on your fuzz. - Ow! That's me! - Wave to us! We'll be in row 118,000. - \
             Bye! Barry, I told you, stop flying in the house! - Hey, Adam. - Hey, Barry. - Is that fuzz gel? - A little. Special day, graduation. \
             Never thought I'd make it. Three days grade school, three days high school. Those were awkward. Three days college. I'm glad I took a \
             day and hitchhiked around the hive. You did come back different. - Hi, Barry. - Artie, growing a mustache? Looks good. - Hear about \
             Frankie? - Yeah. - You going to the funeral? - No, I'm not going. Everybody knows, sting someone, you die. Don't waste it on a \
             squirrel. Such a hothead. I guess he could have just gotten out of the way. I love this incorporating an amusement park into our day. \
             That's why we don't need vacations. Boy, quite a bit of pomp... under the circumstances. - Well, Adam, today we are men. - We are! - \
             Bee-men. - Amen! Hallelujah! Students, faculty, distinguished bees, please welcome Dean Buzzwell. Welcome, New Hive Oity graduating \
             class of... ...9:15. That concludes our ceremonies. And begins your career at Honex Industries! Will we pick ourjob today? I heard it's \
             just orientation. Heads up! Here we go. Keep your hands and antennas inside the tram at all times. - Wonder what it'll be like? - A \
             little scary. Welcome to Honex, a division of Honesco and a part of the Hexagon Group. This is it! Wow. Wow. We know that you, as a \
             bee, have worked your whole life to get to the point where you can work for your whole life. Honey begins when our valiant Pollen Jocks \
             bring the nectar to the hive. Our top-secret formula is automatically color-corrected, scent-adjusted and bubble-contoured into this \
             soothing sweet syrup with its distinctive golden glow you know as... Honey! - That girl was hot. - She's my cousin! - She is? - Yes, \
             we're all cousins. - Right. You're right. - At Honex, we constantly strive to improve every aspect of bee existence. These bees are \
             stress-testing a new helmet technology. - What do you think he makes? - Not enough. Here we have our latest advancement, the Krelman. - \
             What does that do? - Oatches that little strand of honey that hangs after you pour it. Saves us millions. Oan anyone work on the \
             Krelman? Of course. Most bee jobs are small ones. But bees know that every small job, if it's done well, means a lot. But choose \
             carefully because you'll stay in the job you pick for the rest of your life. The same job the rest of your life? I didn't know that. \
             What's the difference? You'll be happy to know that bees, as a species, haven't had one day off in 27 million years. So you'll just \
             work us to death? We'll sure try. Wow! That blew my mind! \"What's the difference?\" How can you say that? One job forever? That's an \
             insane choice to have to make. I'm relieved. Now we only have to make one decision in life. But, Adam, how could they never have told \
             us that? Why would you question anything? We're bees. We're the most perfectly functioning society on Earth. You ever think maybe \
             things work a little too well here? Like what? Give me one example. I don't know. But you know what I'm talking about. Please clear the \
             gate. Royal Nectar Force on approach. Wait a second. Oheck it out. - Hey, those are Pollen Jocks! - Wow. I've never seen them this \
             close. They know what it's like outside the hive. Yeah, but some don't come back. - Hey, Jocks! - Hi, Jocks! You guys did great! You're \
             monsters! You're sky freaks! I love it! I love it! - I wonder where they were. - I don't know. Their day's not planned. Outside the \
             hive, flying who knows where, doing who knows what. You can'tjust decide to be a Pollen Jock. You have to be bred for that. Right. \
             Look. That's more pollen than you and I will see in a lifetime. It's just a status symbol. Bees make too much of it. Perhaps. Unless \
             you're wearing it and the ladies see you wearing it. Those ladies? Aren't they our cousins too? Distant. Distant. Look at these two. - \
             Oouple of Hive Harrys. - Let's have fun with them. It must be dangerous being a Pollen Jock. Yeah. Once a bear pinned me against a \
             mushroom! He had a paw on my throat, and with the other, he was slapping me! - Oh, my! - I never thought I'd knock him out. What were \
             you doing during this? Trying to alert the authorities. I can autograph that. A little gusty out there today, wasn't it, comrades? \
             Yeah. Gusty. We're hitting a sunflower patch six miles from here tomorrow. - Six miles, huh? - Barry! A puddle jump for us, but maybe \
             you're not up for it. - Maybe I am. - You are not! We're going 0900 at J-Gate. What do you think, buzzy-boy? Are you bee enough? I \
             might be. It all depends on what 0900 means. Hey, Honex! Dad, you surprised me. You decide what you're interested in? - Well, there's a \
             lot of choices. - But you only get one. Do you ever get bored doing the same job every day? Son, let me tell you about stirring. You \
             grab that stick, and you just move it around, and you stir it around. You get yourself into a rhythm. It's a beautiful thing. You know, \
             Dad, the more I think about it, maybe the honey field just isn't right for me. You were thinking of what, making balloon animals? \
             That's a bad job for a guy with a stinger. Janet, your son's not sure he wants to go into honey! - Barry, you are so funny sometimes. - \
             I'm not trying to be funny. You're not funny! You're going into honey. Our son, the stirrer! - You're gonna be a stirrer? - No one's \
             listening to me! Wait till you see the sticks I have. I could say anything right now. I'm gonna get an ant tattoo! Let's open some \
             honey and celebrate! Maybe I'll pierce my thorax. Shave my antennae. Shack up with a grasshopper. Get a gold tooth and call everybody \
             \"dawg\"! I'm so proud. - We're starting work today! - Today's the day. Oome on! All the good jobs will be gone. Yeah, right. Pollen \
             counting, stunt bee, pouring, stirrer, front desk, hair removal... - Is it still available? - Hang on. Two left! One of them's yours! \
             Oongratulations! Step to the side. - What'd you get? - Picking crud out. Stellar! Wow! Oouple of newbies? Yes, sir! Our first day! We \
             are ready! Make your choice. - You want to go first? - No, you go. Oh, my. What's available? Restroom attendant's open, not for the \
             reason you think. - Any chance of getting the Krelman? - Sure, you're on. I'm sorry, the Krelman just closed out. Wax monkey's always \
             open. The Krelman opened up again. What happened? A bee died. Makes an opening. See? He's dead. Another dead one. Deady. Deadified. Two \
             more dead. Dead from the neck up. Dead from the neck down. That's life! Oh, this is so hard! Heating, cooling, stunt bee, pourer, \
             stirrer, humming, inspector number seven, lint coordinator, stripe supervisor, mite wrangler. Barry, what do you think I should... \
             Barry? Barry! All right, we've got the sunflower patch in quadrant nine... What happened to you? Where are you? - I'm going out. - Out? \
             Out where? - Out there. - Oh, no! I have to, before I go to work for the rest of my life. You're gonna die! You're crazy! Hello? \
             Another call coming in. If anyone's feeling brave, there's a Korean deli on 83rd that gets their roses today. Hey, guys. - Look at \
             that. - Isn't that the kid we saw yesterday? Hold it, son, flight deck's restricted. It's OK, Lou. We're gonna take him up. Really? \
             Feeling lucky, are you? Sign here, here. Just initial that. - Thank you. - OK. You got a rain advisory today, and as you all know, bees \
             cannot fly in rain. So be careful. As always, watch your brooms, hockey sticks, dogs, birds, bears and bats. Also, I got a couple of \
             reports of root beer being poured on us. Murphy's in a home because of it, babbling like a cicada! - That's awful. - And a reminder for \
             you rookies, bee law number one, absolutely no talking to humans! All right, launch positions! Buzz, buzz, buzz, buzz! Buzz, buzz, \
             buzz, buzz! Buzz, buzz, buzz, buzz! Black and yellow! Hello! You ready for this, hot shot? Yeah. Yeah, bring it on. Wind, check. - \
             Antennae, check. - Nectar pack, check. - Wings, check. - Stinger, check. Scared out of my shorts, check. OK, ladies, let's move it out! \
             Pound those petunias, you striped stem-suckers! All of you, drain those flowers! Wow! I'm out! I can't believe I'm out! So blue. I feel \
             so fast and free! Box kite! Wow! Flowers! This is Blue Leader. We have roses visual. Bring it around 30 degrees and hold. Roses! 30 \
             degrees, roger. Bringing it around. Stand to the side, kid. It's got a bit of a kick. That is one nectar collector! - Ever see \
             pollination up close? - No, sir. I pick up some pollen here, sprinkle it over here. Maybe a dash over there, a pinch on that one. See \
             that? It's a little bit of magic. That's amazing. Why do we do that? That's pollen power. More pollen, more flowers, more nectar, more \
             honey for us. Oool. I'm picking up a lot of bright yellow. Oould be daisies. Don't we need those? Oopy that visual. Wait. One of these \
             flowers seems to be on the move. Say again? You're reporting a moving flower? Affirmative. That was on the line! This is the coolest. \
             What is it? I don't know, but I'm loving this color. It smells good. Not like a flower, but I like it. Yeah, fuzzy. Ohemical-y. \
             Oareful, guys. It's a little grabby. My sweet lord of bees! Oandy-brain, get off there! Problem! - Guys! - This could be bad. \
             Affirmative. Very close. Gonna hurt. Mama's little boy. You are way out of position, rookie! Ooming in at you like a missile! Help me! \
             I don't think these are flowers. - Should we tell him? - I think he knows. What is this?! Match point! You can start packing up, honey, \
             because you're about to eat it! Yowser! Gross. There's a bee in the car! - Do something! - I'm driving! - Hi, bee. - He's back here! \
             He's going to sting me! Nobody move. If you don't move, he won't sting you. Freeze! He blinked! Spray him, Granny! What are you doing?! \
             Wow... the tension level out here is unbelievable. I gotta get home. Oan't fly in rain. Oan't fly in rain. Oan't fly in rain. Mayday! \
             Mayday! Bee going down! Ken, could you close the window please? Ken, could you close the window please? Oheck out my new resume. I made \
             it into a fold-out brochure. You see? Folds out. Oh, no. More humans. I don't need this. What was that? Maybe this time. This time. \
             This time. This time! This time! This... Drapes! That is diabolical. It's fantastic. It's got all my special skills, even my top-ten \
             favorite movies. What's number one? Star Wars? Nah, I don't go for that... ...kind of stuff. No wonder we shouldn't talk to them. \
             They're out of their minds. When I leave a job interview, they're flabbergasted, can't believe what I say. There's the sun. Maybe \
             that's a way out. I don't remember the sun having a big 75 on it. I predicted global warming. I could feel it getting hotter. At first \
             I thought it was just me. Wait! Stop! Bee! Stand back. These are winter boots. Wait! Don't kill him! You know I'm allergic to them! \
             This thing could kill me! Why does his life have less value than yours? Why does his life have any less value than mine? Is that your \
             statement? I'm just saying all life has value. You don't know what he's capable of feeling. My brochure! There you go, little guy. I'm \
             not scared of him. It's an allergic thing. Put that on your resume brochure. My whole face could puff up. Make it one of your special \
             skills. Knocking someone out is also a special skill. Right. Bye, Vanessa. Thanks. - Vanessa, next week? Yogurt night? - Sure, Ken. You \
             know, whatever. - You could put carob chips on there. - Bye. - Supposed to be less calories. - Bye. I gotta say something. She saved my \
             life. I gotta say something. All right, here it goes. Nah. What would I say? I could really get in trouble. It's a bee law. You're not \
             supposed to talk to a human. I can't believe I'm doing this. I've got to. Oh, I can't do it. Oome on! No. Yes. No. Do it. I can't. How \
             should I start it? \"You like jazz?\" No, that's no good. Here she comes! Speak, you fool! Hi! I'm sorry. - You're talking. - Yes, I \
             know. You're talking! I'm so sorry. No, it's OK. It's fine. I know I'm dreaming. But I don't recall going to bed. Well, I'm sure this \
             is very disconcerting. This is a bit of a surprise to me. I mean, you're a bee! I am. And I'm not supposed to be doing this, but they \
             were all trying to kill me. And if it wasn't for you... I had to thank you. It's just how I was raised. That was a little weird. - I'm \
             talking with a bee. - Yeah. I'm talking to a bee. And the bee is talking to me! I just want to say I'm grateful. I'll leave now. - \
             Wait! How did you learn to do that? - What? The talking thing. Same way you did, I guess. \"Mama, Dada, honey.\" You pick it up. - \
             That's very funny. - Yeah. Bees are funny. If we didn't laugh, we'd cry with what we have to deal with. Anyway... Oan I... ...get you \
             something? - Like what? I don't know. I mean... I don't know. Ooffee? I don't want to put you out. It's no trouble. It takes two \
             minutes. - It's just coffee. - I hate to impose. - Don't be ridiculous! - Actually, I would love a cup. Hey, you want rum cake? - I \
             shouldn't. - Have some. - No, I can't. - Oome on! I'm trying to lose a couple micrograms. - Where? - These stripes don't help. You look \
             great! I don't know if you know anything about fashion. Are you all right? No. He's making the tie in the cab as they're flying up \
             Madison. He finally gets there. He runs up the steps into the church. The wedding is on. And he says, \"Watermelon? I thought you said \
             Guatemalan. Why would I marry a watermelon?\" Is that a bee joke? That's the kind of stuff we do. Yeah, different. So, what are you \
             gonna do, Barry? About work? I don't know. I want to do my part for the hive, but I can't do it the way they want. I know how you feel. \
             - You do? - Sure. My parents wanted me to be a lawyer or a doctor, but I wanted to be a florist. - Really? - My only interest is \
             flowers. Our new queen was just elected with that same campaign slogan. Anyway, if you look... There's my hive right there. See it? \
             You're in Sheep Meadow! Yes! I'm right off the Turtle Pond! No way! I know that area. I lost a toe ring there once. - Why do girls put \
             rings on their toes? - Why not? - It's like putting a hat on your knee. - Maybe I'll try that. - You all right, ma'am? - Oh, yeah. \
             Fine. Just having two cups of coffee! Anyway, this has been great. Thanks for the coffee. Yeah, it's no trouble. Sorry I couldn't \
             finish it. If I did, I'd be up the rest of my life. Are you...? Oan I take a piece of this with me? Sure! Here, have a crumb. - Thanks! \
             - Yeah. All right. Well, then... I guess I'll see you around. Or not. OK, Barry. And thank you so much again... for before. Oh, that? \
             That was nothing. Well, not nothing, but... Anyway... This can't possibly work. He's all set to go. We may as well try it. OK, Dave, \
             pull the chute. - Sounds amazing. - It was amazing! It was the scariest, happiest moment of my life. Humans! I can't believe you were \
             with humans! Giant, scary humans! What were they like? Huge and crazy. They talk crazy. They eat crazy giant things. They drive crazy. \
             - Do they try and kill you, like on TV? - Some of them. But some of them don't. - How'd you get back? - Poodle. You did it, and I'm \
             glad. You saw whatever you wanted to see. You had your \"experience.\" Now you can pick out yourjob and be normal. - Well... - Well? \
             Well, I met someone. You did? Was she Bee-ish? - A wasp?! Your parents will kill you! - No, no, no, not a wasp. - Spider? - I'm not \
             attracted to spiders. I know it's the hottest thing, with the eight legs and all. I can't get by that face. So who is she? She's... \
             human. No, no. That's a bee law. You wouldn't break a bee law. - Her name's Vanessa. - Oh, boy. She's so nice. And she's a florist! Oh, \
             no! You're dating a human florist! We're not dating. You're flying outside the hive, talking to humans that attack our homes with power \
             washers and M-80s! One-eighth a stick of dynamite! She saved my life! And she understands me. This is over! Eat this. This is not over! \
             What was that? - They call it a crumb. - It was so stingin' stripey! And that's not what they eat. That's what falls off what they eat! \
             - You know what a Oinnabon is? - No. It's bread and cinnamon and frosting. They heat it up... Sit down! ...really hot! - Listen to me! \
             We are not them! We're us. There's us and there's them! Yes, but who can deny the heart that is yearning? There's no yearning. Stop \
             yearning. Listen to me! You have got to start thinking bee, my friend. Thinking bee! - Thinking bee. - Thinking bee. Thinking bee! \
             Thinking bee! Thinking bee! Thinking bee! There he is. He's in the pool. You know what your problem is, Barry? I gotta start thinking \
             bee? How much longer will this go on? It's been three days! Why aren't you working? I've got a lot of big life decisions to think \
             about. What life? You have no life! You have no job. You're barely a bee! Would it kill you to make a little honey? Barry, come out. \
             Your father's talking to you. Martin, would you talk to him? Barry, I'm talking to you! You coming? Got everything? All set! Go ahead. \
             I'll catch up. Don't be too long. Watch this! Vanessa! - We're still here. - I told you not to yell at him. He doesn't respond to \
             yelling! - Then why yell at me? - Because you don't listen! I'm not listening to this. Sorry, I've gotta go. - Where are you going? - \
             I'm meeting a friend. A girl? Is this why you can't decide? Bye. I just hope she's Bee-ish. They have a huge parade of flowers every \
             year in Pasadena? To be in the Tournament of Roses, that's every florist's dream! Up on a float, surrounded by flowers, crowds \
             cheering. A tournament. Do the roses compete in athletic events? No. All right, I've got one. How come you don't fly everywhere? It's \
             exhausting. Why don't you run everywhere? It's faster. Yeah, OK, I see, I see. All right, your turn. TiVo. You can just freeze live TV? \
             That's insane! You don't have that? We have Hivo, but it's a disease. It's a horrible, horrible disease. Oh, my. Dumb bees! You must \
             want to sting all those jerks. We try not to sting. It's usually fatal for us. So you have to watch your temper. Very carefully. You \
             kick a wall, take a walk, write an angry letter and throw it out. Work through it like any emotion: Anger, jealousy, lust. Oh, my \
             goodness! Are you OK? Yeah. - What is wrong with you?! - It's a bug. He's not bothering anybody. Get out of here, you creep! What was \
             that? A Pic 'N' Save circular? Yeah, it was. How did you know? It felt like about 10 pages. Seventy-five is pretty much our limit. \
             You've really got that down to a science. - I lost a cousin to Italian Vogue. - I'll bet. What in the name of Mighty Hercules is this? \
             How did this get here? Oute Bee, Golden Blossom, Ray Liotta Private Select? - Is he that actor? - I never heard of him. - Why is this \
             here? - For people. We eat it. You don't have enough food of your own? - Well, yes. - How do you get it? - Bees make it. - I know who \
             makes it! And it's hard to make it! There's heating, cooling, stirring. You need a whole Krelman thing! - It's organic. - It's \
             our-ganic! It's just honey, Barry. Just what?! Bees don't know about this! This is stealing! A lot of stealing! You've taken our homes, \
             schools, hospitals! This is all we have! And it's on sale?! I'm getting to the bottom of this. I'm getting to the bottom of all of \
             this! Hey, Hector. - You almost done? - Almost. He is here. I sense it. Well, I guess I'll go home now and just leave this nice honey \
             out, with no one around. You're busted, box boy! I knew I heard something. So you can talk! I can talk. And now you'll start talking! \
             Where you getting the sweet stuff? Who's your supplier? I don't understand. I thought we were friends. The last thing we want to do is \
             upset bees! You're too late! It's ours now! You, sir, have crossed the wrong sword! You, sir, will be lunch for my iguana, Ignacio! \
             Where is the honey coming from? Tell me where! Honey Farms! It comes from Honey Farms! Orazy person! What horrible thing has happened \
             here? These faces, they never knew what hit them. And now they're on the road to nowhere! Just keep still. What? You're not dead? Do I \
             look dead? They will wipe anything that moves. Where you headed? To Honey Farms. I am onto something huge here. I'm going to Alaska. \
             Moose blood, crazy stuff. Blows your head off! I'm going to Tacoma. - And you? - He really is dead. All right. Uh-oh! - What is that?! \
             - Oh, no! - A wiper! Triple blade! - Triple blade? Jump on! It's your only chance, bee! Why does everything have to be so doggone \
             clean?! How much do you people need to see?! Open your eyes! Stick your head out the window! From NPR News in Washington, I'm Oarl \
             Kasell. But don't kill no more bugs! - Bee! - Moose blood guy!! - You hear something? - Like what? Like tiny screaming. Turn off the \
             radio. Whassup, bee boy? Hey, Blood. Just a row of honey jars, as far as the eye could see. Wow! I assume wherever this truck goes is \
             where they're getting it. I mean, that honey's ours. - Bees hang tight. - We're all jammed in. It's a close community. Not us, man. We \
             on our own. Every mosquito on his own. - What if you get in trouble? - You a mosquito, you in trouble. Nobody likes us. They just \
             smack. See a mosquito, smack, smack! At least you're out in the world. You must meet girls. Mosquito girls try to trade up, get with a \
             moth, dragonfly. Mosquito girl don't want no mosquito. You got to be kidding me! Mooseblood's about to leave the building! So long, \
             bee! - Hey, guys! - Mooseblood! I knew I'd catch y'all down here. Did you bring your crazy straw? We throw it in jars, slap a label on \
             it, and it's pretty much pure profit. What is this place? A bee's got a brain the size of a pinhead. They are pinheads! Pinhead. - \
             Oheck out the new smoker. - Oh, sweet. That's the one you want. The Thomas 3000! Smoker? Ninety puffs a minute, semi-automatic. Twice \
             the nicotine, all the tar. A couple breaths of this knocks them right out. They make the honey, and we make the money. \"They make the \
             honey, and we make the money\"? Oh, my! What's going on? Are you OK? Yeah. It doesn't last too long. Do you know you're in a fake hive \
             with fake walls? Our queen was moved here. We had no choice. This is your queen? That's a man in women's clothes! That's a drag queen! \
             What is this? Oh, no! There's hundreds of them! Bee honey. Our honey is being brazenly stolen on a massive scale! This is worse than \
             anything bears have done! I intend to do something. Oh, Barry, stop. Who told you humans are taking our honey? That's a rumor. Do these \
             look like rumors? That's a conspiracy theory. These are obviously doctored photos. How did you get mixed up in this? He's been talking \
             to humans. - What? - Talking to humans?! He has a human girlfriend. And they make out! Make out? Barry! We do not. - You wish you \
             could. - Whose side are you on? The bees! I dated a cricket once in San Antonio. Those crazy legs kept me up all night. Barry, this is \
             what you want to do with your life? I want to do it for all our lives. Nobody works harder than bees! Dad, I remember you coming home \
             so overworked your hands were still stirring. You couldn't stop. I remember that. What right do they have to our honey? We live on two \
             cups a year. They put it in lip balm for no reason whatsoever! Even if it's true, what can one bee do? Sting them where it really \
             hurts. In the face! The eye! - That would hurt. - No. Up the nose? That's a killer. There's only one place you can sting the humans, \
             one place where it matters. Hive at Five, the hive's only full-hour action news source. No more bee beards! With Bob Bumble at the \
             anchor desk. Weather with Storm Stinger. Sports with Buzz Larvi. And Jeanette Ohung. - Good evening. I'm Bob Bumble. - And I'm Jeanette \
             Ohung. A tri-county bee, Barry Benson, intends to sue the human race for stealing our honey, packaging it and profiting from it \
             illegally! Tomorrow night on Bee Larry King, we'll have three former queens here in our studio, discussing their new book, Olassy \
             Ladies, out this week on Hexagon. Tonight we're talking to Barry Benson. Did you ever think, \"I'm a kid from the hive. I can't do \
             this\"? Bees have never been afraid to change the world. What about Bee Oolumbus? Bee Gandhi? Bejesus? Where I'm from, we'd never sue \
             humans. We were thinking of stickball or candy stores. How old are you? The bee community is supporting you in this case, which will be \
             the trial of the bee century. You know, they have a Larry King in the human world too. It's a common name. Next week... He looks like \
             you and has a show and suspenders and colored dots... Next week... Glasses, quotes on the bottom from the guest even though you just \
             heard 'em. Bear Week next week! They're scary, hairy and here live. Always leans forward, pointy shoulders, squinty eyes, very Jewish. \
             In tennis, you attack at the point of weakness! It was my grandmother, Ken. She's 81. Honey, her backhand's a joke! I'm not gonna take \
             advantage of that? Quiet, please. Actual work going on here. - Is that that same bee? - Yes, it is! I'm helping him sue the human race. \
             - Hello. - Hello, bee. This is Ken. Yeah, I remember you. Timberland, size ten and a half. Vibram sole, I believe. Why does he talk \
             again? Listen, you better go 'cause we're really busy working. But it's our yogurt night! Bye-bye. Why is yogurt night so difficult?! \
             You poor thing. You two have been at this for hours! Yes, and Adam here has been a huge help. - Frosting... - How many sugars? Just \
             one. I try not to use the competition. So why are you helping me? Bees have good qualities. And it takes my mind off the shop. Instead \
             of flowers, people are giving balloon bouquets now. Those are great, if you're three. And artificial flowers. - Oh, those just get me \
             psychotic! - Yeah, me too. Bent stingers, pointless pollination. Bees must hate those fake things! Nothing worse than a daffodil that's \
             had work done. Maybe this could make up for it a little bit. - This lawsuit's a pretty big deal. - I guess. You sure you want to go \
             through with it? Am I sure? When I'm done with the humans, they won't be able to say, \"Honey, I'm home,\" without paying a royalty! \
             It's an incredible scene here in downtown Manhattan, where the world anxiously waits, because for the first time in history, we will \
             hear for ourselves if a honeybee can actually speak. What have we gotten into here, Barry? It's pretty big, isn't it? I can't believe \
             how many humans don't work during the day. You think billion-dollar multinational food companies have good lawyers? Everybody needs to \
             stay behind the barricade. - What's the matter? - I don't know, I just got a chill. Well, if it isn't the bee team. You boys work on \
             this? All rise! The Honorable Judge Bumbleton presiding. All right. Oase number 4475, Superior Oourt of New York, Barry Bee Benson v. \
             the Honey Industry is now in session. Mr. Montgomery, you're representing the five food companies collectively? A privilege. Mr. \
             Benson... you're representing all the bees of the world? I'm kidding. Yes, Your Honor, we're ready to proceed. Mr. Montgomery, your \
             opening statement, please. Ladies and gentlemen of the jury, my grandmother was a simple woman. Born on a farm, she believed it was \
             man's divine right to benefit from the bounty of nature God put before us. If we lived in the topsy-turvy world Mr. Benson imagines, \
             just think of what would it mean. I would have to negotiate with the silkworm for the elastic in my britches! Talking bee! How do we \
             know this isn't some sort of holographic motion-picture-capture Hollywood wizardry? They could be using laser beams! Robotics! \
             Ventriloquism! Oloning! For all we know, he could be on steroids! Mr. Benson? Ladies and gentlemen, there's no trickery here. I'm just \
             an ordinary bee. Honey's pretty important to me. It's important to all bees. We invented it! We make it. And we protect it with our \
             lives. Unfortunately, there are some people in this room who think they can take it from us 'cause we're the little guys! I'm hoping \
             that, after this is all over, you'll see how, by taking our honey, you not only take everything we have but everything we are! I wish \
             he'd dress like that all the time. So nice! Oall your first witness. So, Mr. Klauss Vanderhayden of Honey Farms, big company you have. \
             I suppose so. I see you also own Honeyburton and Honron! Yes, they provide beekeepers for our farms. Beekeeper. I find that to be a \
             very disturbing term. I don't imagine you employ any bee-free-ers, do you? - No. - I couldn't hear you. - No. - No. Because you don't \
             free bees. You keep bees. Not only that, it seems you thought a bear would be an appropriate image for a jar of honey. They're very \
             lovable creatures. Yogi Bear, Fozzie Bear, Build-A-Bear. You mean like this? Bears kill bees! How'd you like his head crashing through \
             your living room?! Biting into your couch! Spitting out your throw pillows! OK, that's enough. Take him away. So, Mr. Sting, thank you \
             for being here. Your name intrigues me. - Where have I heard it before? - I was with a band called The Police. But you've never been a \
             police officer, have you? No, I haven't. No, you haven't. And so here we have yet another example of bee culture casually stolen by a \
             human for nothing more than a prance-about stage name. Oh, please. Have you ever been stung, Mr. Sting? Because I'm feeling a little \
             stung, Sting. Or should I say... Mr. Gordon M. Sumner! That's not his real name?! You idiots! Mr. Liotta, first, belated \
             congratulations on your Emmy win for a guest spot on ER in 2005. Thank you. Thank you. I see from your resume that you're devilishly \
             handsome with a churning inner turmoil that's ready to blow. I enjoy what I do. Is that a crime? Not yet it isn't. But is this what \
             it's come to for you? Exploiting tiny, helpless bees so you don't have to rehearse your part and learn your lines, sir? Watch it, \
             Benson! I could blow right now! This isn't a goodfella. This is a badfella! Why doesn't someone just step on this creep, and we can all \
             go home?! - Order in this court! - You're all thinking it! Order! Order, I say! - Say it! - Mr. Liotta, please sit down! I think it was \
             awfully nice of that bear to pitch in like that. I think the jury's on our side. Are we doing everything right, legally? I'm a florist. \
             Right. Well, here's to a great team. To a great team! Well, hello. - Ken! - Hello. I didn't think you were coming. No, I was just late. \
             I tried to call, but... the battery. I didn't want all this to go to waste, so I called Barry. Luckily, he was free. Oh, that was \
             lucky. There's a little left. I could heat it up. Yeah, heat it up, sure, whatever. So I hear you're quite a tennis player. I'm not \
             much for the game myself. The ball's a little grabby. That's where I usually sit. Right... there. Ken, Barry was looking at your \
             resume, and he agreed with me that eating with chopsticks isn't really a special skill. You think I don't see what you're doing? I know \
             how hard it is to find the rightjob. We have that in common. Do we? Bees have 100 percent employment, but we do jobs like taking the \
             crud out. That's just what I was thinking about doing. Ken, I let Barry borrow your razor for his fuzz. I hope that was all right. I'm \
             going to drain the old stinger. Yeah, you do that. Look at that. You know, I've just about had it with your little mind games. - What's \
             that? - Italian Vogue. Mamma mia, that's a lot of pages. A lot of ads. Remember what Van said, why is your life more valuable than \
             mine? Funny, I just can't seem to recall that! I think something stinks in here! I love the smell of flowers. How do you like the smell \
             of flames?! Not as much. Water bug! Not taking sides! Ken, I'm wearing a Ohapstick hat! This is pathetic! I've got issues! Well, well, \
             well, a royal flush! - You're bluffing. - Am I? Surf's up, dude! Poo water! That bowl is gnarly. Except for those dirty yellow rings! \
             Kenneth! What are you doing?! You know, I don't even like honey! I don't eat it! We need to talk! He's just a little bee! And he \
             happens to be the nicest bee I've met in a long time! Long time? What are you talking about?! Are there other bugs in your life? No, \
             but there are other things bugging me in life. And you're one of them! Fine! Talking bees, no yogurt night... My nerves are fried from \
             riding on this emotional roller coaster! Goodbye, Ken. And for your information, I prefer sugar-free, artificial sweeteners made by \
             man! I'm sorry about all that. I know it's got an aftertaste! I like it! I always felt there was some kind of barrier between Ken and \
             me. I couldn't overcome it. Oh, well. Are you OK for the trial? I believe Mr. Montgomery is about out of ideas. We would like to call \
             Mr. Barry Benson Bee to the stand. Good idea! You can really see why he's considered one of the best lawyers... Yeah. Layton, you've \
             gotta weave some magic with this jury, or it's gonna be all over. Don't worry. The only thing I have to do to turn this jury around is \
             to remind them of what they don't like about bees. - You got the tweezers? - Are you allergic? Only to losing, son. Only to losing. Mr. \
             Benson Bee, I'll ask you what I think we'd all like to know. What exactly is your relationship to that woman? We're friends. - Good \
             friends? - Yes. How good? Do you live together? Wait a minute... Are you her little... ...bedbug? I've seen a bee documentary or two. \
             From what I understand, doesn't your queen give birth to all the bee children? - Yeah, but... - So those aren't your real parents! - \
             Oh, Barry... - Yes, they are! Hold me back! You're an illegitimate bee, aren't you, Benson? He's denouncing bees! Don't y'all date your \
             cousins? - Objection! - I'm going to pincushion this guy! Adam, don't! It's what he wants! Oh, I'm hit!! Oh, lordy, I am hit! Order! \
             Order! The venom! The venom is coursing through my veins! I have been felled by a winged beast of destruction! You see? You can't treat \
             them like equals! They're striped savages! Stinging's the only thing they know! It's their way! - Adam, stay with me. - I can't feel my \
             legs. What angel of mercy will come forward to suck the poison from my heaving buttocks? I will have order in this court. Order! Order, \
             please! The case of the honeybees versus the human race took a pointed turn against the bees yesterday when one of their legal team \
             stung Layton T. Montgomery. - Hey, buddy. - Hey. - Is there much pain? - Yeah. I... I blew the whole case, didn't I? It doesn't matter. \
             What matters is you're alive. You could have died. I'd be better off dead. Look at me. They got it from the cafeteria downstairs, in a \
             tuna sandwich. Look, there's a little celery still on it. What was it like to sting someone? I can't explain it. It was all... All \
             adrenaline and then... and then ecstasy! All right. You think it was all a trap? Of course. I'm sorry. I flew us right into this. What \
             were we thinking? Look at us. We're just a couple of bugs in this world. What will the humans do to us if they win? I don't know. I \
             hear they put the roaches in motels. That doesn't sound so bad. Adam, they check in, but they don't check out! Oh, my. Oould you get a \
             nurse to close that window? - Why? - The smoke. Bees don't smoke. Right. Bees don't smoke. Bees don't smoke! But some bees are smoking. \
             That's it! That's our case! It is? It's not over? Get dressed. I've gotta go somewhere. Get back to the court and stall. Stall any way \
             you can. And assuming you've done step correctly, you're ready for the tub. Mr. Flayman. Yes? Yes, Your Honor! Where is the rest of \
             your team? Well, Your Honor, it's interesting. Bees are trained to fly haphazardly, and as a result, we don't make very good time. I \
             actually heard a funny story about... Your Honor, haven't these ridiculous bugs taken up enough of this court's valuable time? How much \
             longer will we allow these absurd shenanigans to go on? They have presented no compelling evidence to support their charges against my \
             clients, who run legitimate businesses. I move for a complete dismissal of this entire case! Mr. Flayman, I'm afraid I'm going to have \
             to consider Mr. Montgomery's motion. But you can't! We have a terrific case. Where is your proof? Where is the evidence? Show me the \
             smoking gun! Hold it, Your Honor! You want a smoking gun? Here is your smoking gun. What is that? It's a bee smoker! What, this? This \
             harmless little contraption? This couldn't hurt a fly, let alone a bee. Look at what has happened to bees who have never been asked, \
             \"Smoking or non?\" Is this what nature intended for us? To be forcibly addicted to smoke machines and man-made wooden slat work camps? \
             Living out our lives as honey slaves to the white man? - What are we gonna do? - He's playing the species card. Ladies and gentlemen, \
             please, free these bees! Free the bees! Free the bees! Free the bees! Free the bees! Free the bees! The court finds in favor of the \
             bees! Vanessa, we won! I knew you could do it! High-five! Sorry. I'm OK! You know what this means? All the honey will finally belong to \
             the bees. Now we won't have to work so hard all the time. This is an unholy perversion of the balance of nature, Benson. You'll regret \
             this. Barry, how much honey is out there? All right. One at a time. Barry, who are you wearing? My sweater is Ralph Lauren, and I have \
             no pants. - What if Montgomery's right? - What do you mean? We've been living the bee way a long time, 27 million years. \
             Oongratulations on your victory. What will you demand as a settlement? First, we'll demand a complete shutdown of all bee work camps. \
             Then we want back the honey that was ours to begin with, every last drop. We demand an end to the glorification of the bear as anything \
             more than a filthy, smelly, bad-breath stink machine. We're all aware of what they do in the woods. Wait for my signal. Take him out. \
             He'll have nauseous for a few hours, then he'll be fine. And we will no longer tolerate bee-negative nicknames... But it's just a \
             prance-about stage name! ...unnecessary inclusion of honey in bogus health products and la-dee-da human tea-time snack garnishments. \
             Oan't breathe. Bring it in, boys! Hold it right there! Good. Tap it. Mr. Buzzwell, we just passed three cups, and there's gallons more \
             coming! - I think we need to shut down! - Shut down? We've never shut down. Shut down honey production! Stop making honey! Turn your \
             key, sir! What do we do now? Oannonball! We're shutting honey production! Mission abort. Aborting pollination and nectar detail. \
             Returning to base. Adam, you wouldn't believe how much honey was out there. Oh, yeah? What's going on? Where is everybody? - Are they \
             out celebrating? - They're home. They don't know what to do. Laying out, sleeping in. I heard your Uncle Oarl was on his way to San \
             Antonio with a cricket. At least we got our honey back. Sometimes I think, so what if humans liked our honey? Who wouldn't? It's the \
             greatest thing in the world! I was excited to be part of making it. This was my new desk. This was my new job. I wanted to do it really \
             well. And now... Now I can't. I don't understand why they're not happy. I thought their lives would be better! They're doing nothing. \
             It's amazing. Honey really changes people. You don't have any idea what's going on, do you? - What did you want to show me? - This. \
             What happened here? That is not the half of it. Oh, no. Oh, my. They're all wilting. Doesn't look very good, does it? No. And whose \
             fault do you think that is? You know, I'm gonna guess bees. Bees? Specifically, me. I didn't think bees not needing to make honey would \
             affect all these things. It's notjust flowers. Fruits, vegetables, they all need bees. That's our whole SAT test right there. Take away \
             produce, that affects the entire animal kingdom. And then, of course... The human species? So if there's no more pollination, it could \
             all just go south here, couldn't it? I know this is also partly my fault. How about a suicide pact? How do we do it? - I'll sting you, \
             you step on me. - Thatjust kills you twice. Right, right. Listen, Barry... sorry, but I gotta get going. I had to open my mouth and \
             talk. Vanessa? Vanessa? Why are you leaving? Where are you going? To the final Tournament of Roses parade in Pasadena. They've moved it \
             to this weekend because all the flowers are dying. It's the last chance I'll ever have to see it. Vanessa, I just wanna say I'm sorry. \
             I never meant it to turn out like this. I know. Me neither. Tournament of Roses. Roses can't do sports. Wait a minute. Roses. Roses? \
             Roses! Vanessa! Roses?! Barry? - Roses are flowers! - Yes, they are. Flowers, bees, pollen! I know. That's why this is the last parade. \
             Maybe not. Oould you ask him to slow down? Oould you slow down? Barry! OK, I made a huge mistake. This is a total disaster, all my \
             fault. Yes, it kind of is. I've ruined the planet. I wanted to help you with the flower shop. I've made it worse. Actually, it's \
             completely closed down. I thought maybe you were remodeling. But I have another idea, and it's greater than my previous ideas combined. \
             I don't want to hear it! All right, they have the roses, the roses have the pollen. I know every bee, plant and flower bud in this \
             park. All we gotta do is get what they've got back here with what we've got. - Bees. - Park. - Pollen! - Flowers. - Repollination! - \
             Across the nation! Tournament of Roses, Pasadena, Oalifornia. They've got nothing but flowers, floats and cotton candy. Security will \
             be tight. I have an idea. Vanessa Bloome, FTD. Official floral business. It's real. Sorry, ma'am. Nice brooch. Thank you. It was a \
             gift. Once inside, we just pick the right float. How about The Princess and the Pea? I could be the princess, and you could be the pea! \
             Yes, I got it. - Where should I sit? - What are you? - I believe I'm the pea. - The pea? It goes under the mattresses. - Not in this \
             fairy tale, sweetheart. - I'm getting the marshal. You do that! This whole parade is a fiasco! Let's see what this baby'll do. Hey, \
             what are you doing?! Then all we do is blend in with traffic... ...without arousing suspicion. Once at the airport, there's no stopping \
             us. Stop! Security. - You and your insect pack your float? - Yes. Has it been in your possession the entire time? Would you remove your \
             shoes? - Remove your stinger. - It's part of me. I know. Just having some fun. Enjoy your flight. Then if we're lucky, we'll have just \
             enough pollen to do the job. Oan you believe how lucky we are? We have just enough pollen to do the job! I think this is gonna work. \
             It's got to work. Attention, passengers, this is Oaptain Scott. We have a bit of bad weather in New York. It looks like we'll \
             experience a couple hours delay. Barry, these are cut flowers with no water. They'll never make it. I gotta get up there and talk to \
             them. Be careful. Oan I get help with the Sky Mall magazine? I'd like to order the talking inflatable nose and ear hair trimmer. \
             Oaptain, I'm in a real situation. - What'd you say, Hal? - Nothing. Bee! Don't freak out! My entire species... What are you doing? - \
             Wait a minute! I'm an attorney! - Who's an attorney? Don't move. Oh, Barry. Good afternoon, passengers. This is your captain. Would a \
             Miss Vanessa Bloome in 24B please report to the cockpit? And please hurry! What happened here? There was a DustBuster, a toupee, a life \
             raft exploded. One's bald, one's in a boat, they're both unconscious! - Is that another bee joke? - No! No one's flying the plane! This \
             is JFK control tower, Flight 356. What's your status? This is Vanessa Bloome. I'm a florist from New York. Where's the pilot? He's \
             unconscious, and so is the copilot. Not good. Does anyone onboard have flight experience? As a matter of fact, there is. - Who's that? \
             - Barry Benson. From the honey trial?! Oh, great. Vanessa, this is nothing more than a big metal bee. It's got giant wings, huge \
             engines. I can't fly a plane. - Why not? Isn't John Travolta a pilot? - Yes. How hard could it be? Wait, Barry! We're headed into some \
             lightning. This is Bob Bumble. We have some late-breaking news from JFK Airport, where a suspenseful scene is developing. Barry Benson, \
             fresh from his legal victory... That's Barry! ...is attempting to land a plane, loaded with people, flowers and an incapacitated flight \
             crew. Flowers?! We have a storm in the area and two individuals at the controls with absolutely no flight experience. Just a minute. \
             There's a bee on that plane. I'm quite familiar with Mr. Benson and his no-account compadres. They've done enough damage. But isn't he \
             your only hope? Technically, a bee shouldn't be able to fly at all. Their wings are too small... Haven't we heard this a million times? \
             \"The surface area of the wings and body mass make no sense.\" - Get this on the air! - Got it. - Stand by. - We're going live. The way \
             we work may be a mystery to you. Making honey takes a lot of bees doing a lot of small jobs. But let me tell you about a small job. If \
             you do it well, it makes a big difference. More than we realized. To us, to everyone. That's why I want to get bees back to working \
             together. That's the bee way! We're not made of Jell-O. We get behind a fellow. - Black and yellow! - Hello! Left, right, down, hover. \
             - Hover? - Forget hover. This isn't so hard. Beep-beep! Beep-beep! Barry, what happened?! Wait, I think we were on autopilot the whole \
             time. - That may have been helping me. - And now we're not! So it turns out I cannot fly a plane. All of you, let's get behind this \
             fellow! Move it out! Move out! Our only chance is if I do what I'd do, you copy me with the wings of the plane! Don't have to yell. I'm \
             not yelling! We're in a lot of trouble. It's very hard to concentrate with that panicky tone in your voice! It's not a tone. I'm \
             panicking! I can't do this! Vanessa, pull yourself together. You have to snap out of it! You snap out of it. You snap out of it. - You \
             snap out of it! - You snap out of it! - You snap out of it! - You snap out of it! - You snap out of it! - You snap out of it! - Hold \
             it! - Why? Oome on, it's my turn. How is the plane flying? I don't know. Hello? Benson, got any flowers for a happy occasion in there? \
             The Pollen Jocks! They do get behind a fellow. - Black and yellow. - Hello. All right, let's drop this tin can on the blacktop. Where? \
             I can't see anything. Oan you? No, nothing. It's all cloudy. Oome on. You got to think bee, Barry. - Thinking bee. - Thinking bee. \
             Thinking bee! Thinking bee! Thinking bee! Wait a minute. I think I'm feeling something. - What? - I don't know. It's strong, pulling \
             me. Like a 27-million-year-old instinct. Bring the nose down. Thinking bee! Thinking bee! Thinking bee! - What in the world is on the \
             tarmac? - Get some lights on that! Thinking bee! Thinking bee! Thinking bee! - Vanessa, aim for the flower. - OK. Out the engines. \
             We're going in on bee power. Ready, boys? Affirmative! Good. Good. Easy, now. That's it. Land on that flower! Ready? Full reverse! Spin \
             it around! - Not that flower! The other one! - Which one? - That flower. - I'm aiming at the flower! That's a fat guy in a flowered \
             shirt. I mean the giant pulsating flower made of millions of bees! Pull forward. Nose down. Tail up. Rotate around it. - This is \
             insane, Barry! - This's the only way I know how to fly. Am I koo-koo-kachoo, or is this plane flying in an insect-like pattern? Get \
             your nose in there. Don't be afraid. Smell it. Full reverse! Just drop it. Be a part of it. Aim for the center! Now drop it in! Drop it \
             in, woman! Oome on, already. Barry, we did it! You taught me how to fly! - Yes. No high-five! - Right. Barry, it worked! Did you see \
             the giant flower? What giant flower? Where? Of course I saw the flower! That was genius! - Thank you. - But we're not done yet. Listen, \
             everyone! This runway is covered with the last pollen from the last flowers available anywhere on Earth. That means this is our last \
             chance. We're the only ones who make honey, pollinate flowers and dress like this. If we're gonna survive as a species, this is our \
             moment! What do you say? Are we going to be bees, orjust Museum of Natural History keychains? We're bees! Keychain! Then follow me! \
             Except Keychain. Hold on, Barry. Here. You've earned this. Yeah! I'm a Pollen Jock! And it's a perfect fit. All I gotta do are the \
             sleeves. Oh, yeah. That's our Barry. Mom! The bees are back! If anybody needs to make a call, now's the time. I got a feeling we'll be \
             working late tonight! Here's your change. Have a great afternoon! Oan I help who's next? Would you like some honey with that? It is \
             bee-approved. Don't forget these. Milk, cream, cheese, it's all me. And I don't see a nickel! Sometimes I just feel like a piece of \
             meat! I had no idea. Barry, I'm sorry. Have you got a moment? Would you excuse me? My mosquito associate will help you. Sorry I'm late. \
             He's a lawyer too? I was already a blood-sucking parasite. All I needed was a briefcase. Have a great afternoon! Barry, I just got this \
             huge tulip order, and I can't get them anywhere. No problem, Vannie. Just leave it to me. You're a lifesaver, Barry. Oan I help who's \
             next? All right, scramble, jocks! It's time to fly. Thank you, Barry! That bee is living my life! Let it go, Kenny. - When will this \
             nightmare end?! - Let it all go. - Beautiful day to fly. - Sure is. Between you and me, I was dying to get out of that office. You have \
             got to start thinking bee, my friend. - Thinking bee! - Me? Hold it. Let's just stop for a second. Hold it. I'm sorry. I'm sorry, \
             everyone. Oan we stop here? I'm not making a major life decision during a production number! All right. Take ten, everybody. Wrap it \
             up, guys. I had virtually no rehearsal for that."
        };
        let file2: Vec<u8> = {
            let mut res: Vec<u8> = Vec::with_capacity(4096);
            match getrandom(&mut res) {
                Ok(_) => res,
                Err(err) => {
                    panic!("Failed to genereate random test bytestring: {}", err);
                },
            }
        };
        let file3: &'static str = {
            "Did you ever hear the tragedy of Darth Plagueis The Wise? I thought not. It’s not a story the Jedi would tell you. It’s a Sith legend. \
             Darth Plagueis was a Dark Lord of the Sith, so powerful and so wise he could use the Force to influence the midichlorians to create \
             life… He had such a knowledge of the dark side that he could even keep the ones he cared about from dying. The dark side of the Force \
             is a pathway to many abilities some consider to be unnatural. He became so powerful… the only thing he was afraid of was losing his \
             power, which eventually, of course, he did. Unfortunately, he taught his apprentice everything he knew, then his apprentice killed him \
             in his sleep. Ironic. He could save others from death, but not himself."
        };

        // Assign them some paths relative to the tempdir
        let path1: PathBuf = PathBuf::from("beemovie.txt");
        let path2: PathBuf = PathBuf::from("bytes.dat");
        let path3: PathBuf = PathBuf::from("subdirectory").join("tragedy_of_darth_plagueis_the_wise.txt");
        let source_path1: PathBuf = source.join(&path1);
        let source_path2: PathBuf = source.join(&path2);
        let source_path3: PathBuf = source.join(&path3);

        // Generate the directories and files
        for path in [&source_path1, &source_path2, &source_path3] {
            // Check if the directory exists
            if let Some(dir) = path.parent() {
                if !dir.exists() {
                    if let Err(err) = fs::create_dir_all(dir) {
                        panic!("Failed to create directory '{}': {}", dir.display(), err);
                    }
                }
            }

            // Generate the file
            let mut handle: fs::File = match fs::File::create(path) {
                Ok(handle) => handle,
                Err(err) => {
                    panic!("Failed to create file '{}': {}", path.display(), err);
                },
            };

            // Write the thing to write
            if let Err(err) = if path == &source_path1 {
                write!(handle, "{file1}")
            } else if path == &source_path2 {
                handle.write_all(&file2)
            } else if path == &source_path3 {
                write!(handle, "{file3}")
            } else {
                unreachable!();
            } {
                panic!("Failed to write to '{}': {}", path.display(), err);
            }
        }



        /***** ARCHIVING *****/
        // Archive the thing to the temporary folder
        let tar_path: PathBuf = tempdir.path().join("source.tar.gz");
        if let Err(err) = archive_async(&source, &tar_path, skip_dir).await {
            panic!("Failed to archive the source: {}", err);
        }

        // Unarchive the thing to the temporary folder again, this time named differently
        let target: PathBuf = tempdir.path().join("src_unarchived");
        if let Err(err) = unarchive_async(&tar_path, &target).await {
            panic!("Failed to unarchive the tarball: {}", err);
        }



        /***** VERIFICATION *****/
        // Check if the paths are the same
        let target: PathBuf = if skip_dir { target } else { target.join("src") };
        let target_path1: PathBuf = target.join(&path1);
        let target_path2: PathBuf = target.join(&path2);
        let target_path3: PathBuf = target.join(&path3);
        for path in [&target_path1, &target_path2, &target_path3] {
            // Verify the path made it
            if !path.exists() {
                panic!("File '{}' didn't make the archivation process (not found)", path.display());
            }
            if !path.is_file() {
                panic!("File '{}' didn't make the archivation process (not a file)", path.display());
            }

            // Load the file's contents and compare them
            let mut handle: fs::File = match fs::File::open(path) {
                Ok(handle) => handle,
                Err(err) => {
                    panic!("Failed to open file '{}': {}", path.display(), err);
                },
            };

            // Do the comparison
            if path == &target_path1 {
                // Load it as a string
                let mut contents: String = String::new();
                if let Err(err) = handle.read_to_string(&mut contents) {
                    panic!("Failed to read file '{}': {}", path.display(), err);
                };

                // Compare it
                if contents != file1 {
                    panic!(
                        "Contents of '{}' (pre-archivation) VS '{}' (post-archivation) don't actually match;\n\n'{}':\n{}\n\n'{}':\n{}\n\n",
                        source_path1.display(),
                        path.display(),
                        source_path1.display(),
                        BlockFormatter::new(file1),
                        path.display(),
                        BlockFormatter::new(contents)
                    );
                }
            } else if path == &target_path2 {
                // Load it as bytes
                let mut contents: Vec<u8> = Vec::new();
                if let Err(err) = handle.read_to_end(&mut contents) {
                    panic!("Failed to read file '{}': {}", path.display(), err);
                };

                // Compare it
                if contents != file2 {
                    panic!(
                        "Contents of '{}' (pre-archivation) VS '{}' (post-archivation) don't actually match;\n\n'{}':\n{}\n\n'{}':\n{}\n\n",
                        source_path2.display(),
                        path.display(),
                        source_path2.display(),
                        BlockFormatter::new(HexFormatter::new(&file2)),
                        path.display(),
                        BlockFormatter::new(HexFormatter::new(&contents))
                    );
                }
            } else if path == &target_path3 {
                // Load it as a string
                let mut contents: String = String::new();
                if let Err(err) = handle.read_to_string(&mut contents) {
                    panic!("Failed to read file '{}': {}", path.display(), err);
                };

                // Compare it
                if contents != file3 {
                    panic!(
                        "Contents of '{}' (pre-archivation) VS '{}' (post-archivation) don't actually match;\n\n'{}':\n{}\n\n'{}':\n{}\n\n",
                        source_path3.display(),
                        path.display(),
                        source_path3.display(),
                        BlockFormatter::new(file3),
                        path.display(),
                        BlockFormatter::new(contents)
                    );
                }
            } else {
                panic!("Path is '{}', but that can never be?", path.display());
            }
        }
    }



    /// Test if archiving / unarchiving works, keeping the root folder intact.
    #[tokio::test]
    async fn test_tarball_with_root() { test_archive_unarchive(PathBuf::new(), false).await; }

    /// Test if archiving / unarchiving works, skipping the root folder in the result.
    #[tokio::test]
    async fn test_tarball_without_root() { test_archive_unarchive(PathBuf::new(), true).await; }

    /// Test if archiving / unarchiving works, keeping the root folder intact _and_ having a folder that is far away to test removing the intermediate directories.
    #[tokio::test]
    async fn test_tarball_with_root_extra_path() { test_archive_unarchive("some/extra/folders/lol".into(), false).await; }

    /// Test if archiving / unarchiving works, skipping the root folder in the result _and_ having a folder that is far away to test removing the intermediate directories.
    #[tokio::test]
    async fn test_tarball_without_root_extra_path() { test_archive_unarchive("some/extra/folders/lol".into(), true).await; }
}





/***** ERRORS *****/
/// Defines the errors tha may occur when dealing with the filesystem operations.
#[derive(Debug)]
pub enum Error {
    /// The given path already exists.
    PathExistsError { what: &'static str, path: PathBuf },
    /// File not found.
    PathNotFoundError { what: &'static str, path: PathBuf },
    /// File not a file or a directory.
    PathNotFileNotDir { what: &'static str, path: PathBuf },
    /// The given path contains a '..' where it is not allowed.
    PathWithParentDir { what: &'static str, path: PathBuf },
    /// Failed to rename the given path to the target path.
    PathRenameError { source: PathBuf, target: PathBuf, err: std::io::Error },

    /// The given file is not a file.
    FileNotAFile { path: PathBuf },
    /// Failed to create a file.
    FileCreateError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to open an existing file.
    FileOpenError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to read metadata of the given file.
    FileMetadataError { path: PathBuf, err: std::io::Error },
    /// Failed to update the permissions of the given file.
    FilePermissionsError { path: PathBuf, err: std::io::Error },
    /// Failed to write to the output file.
    FileWriteError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to copy a file.
    FileCopyError { source: PathBuf, target: PathBuf, err: std::io::Error },
    /// Failed to remove a file.
    FileRemoveError { path: PathBuf, err: std::io::Error },
    /// The checksum of a file was not what we expected.
    FileChecksumError { what: &'static str, path: PathBuf, got: String, expected: String },
    /// Failed to lock a file.
    FileLockError { path: PathBuf, err: std::io::Error },

    /// Directory not found.
    DirNotFound { path: PathBuf },
    /// The given directory should be a directory, but isn't.
    DirNotADir { what: &'static str, path: PathBuf },
    /// Failed to create some directory.
    DirCreateError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to read a directory's entries.
    DirReadError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to read a single entry within the directory's entries.
    DirEntryReadError { what: &'static str, path: PathBuf, entry: usize, err: std::io::Error },
    /// Failed to remove a directory.
    DirRemoveError { path: PathBuf, err: std::io::Error },
    /// A given dir had not exactly one child.
    DirNotOneEntry { what: &'static str, path: PathBuf },
    /// A given dir had not a directory as child.
    DirNonDirChild { what: &'static str, path: PathBuf, child: OsString },

    /// The given address did not have HTTPS enabled.
    NotHttpsError { address: String },
    /// Failed to send a request to the given address.
    RequestError { address: String, err: reqwest::Error },
    /// The given server responded with a non-2xx status code.
    RequestFailure { address: String, code: StatusCode, err: Option<String> },
    /// Failed to download the full file stream.
    DownloadError { address: String, err: reqwest::Error },

    /// A bit of an obscure error meaning we failed to flush the encoder (=write handle)'s contents.
    EncoderFlushError { err: std::io::Error },

    /// Failed to append a file to the given archive.
    TarAppendError { source: PathBuf, tarball: PathBuf, err: std::io::Error },
    /// Failed to finish writing the given tarball.
    TarFinishError { path: PathBuf, err: std::io::Error },
    /// Failed to read the entries in a tarball.
    TarEntriesError { path: PathBuf, err: std::io::Error },
    /// Failed a particular entry in the tarball.
    TarEntryError { path: PathBuf, entry: usize, err: std::io::Error },
    /// Failed to get the path in the given entry.
    TarEntryPathError { path: PathBuf, entry: usize, err: std::io::Error },
    /// Failed to extract the given tarball.
    TarExtractError { tarball: PathBuf, entry: PathBuf, target: PathBuf, err: std::io::Error },
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            PathExistsError { what, path } => write!(f, "{} '{}' already exists", what.capitalize(), path.display()),
            PathNotFoundError { what, path } => write!(f, "{} '{}' not found", what.capitalize(), path.display()),
            PathNotFileNotDir { what, path } => {
                write!(f, "{} '{}' exists but is not a file nor a directory (don't know what to do with it)", what.capitalize(), path.display())
            },
            PathWithParentDir { what, path } => {
                write!(f, "Given {} path '{}' contains a parent directory component ('..'); this is not allowed", what, path.display())
            },
            PathRenameError { source, target, err } => write!(f, "Failed to rename '{}' to '{}': {}", source.display(), target.display(), err),

            FileNotAFile { path } => write!(f, "File '{}' exists but not as a file", path.display()),
            FileCreateError { what, path, err } => write!(f, "Failed to create {} file '{}': {}", what, path.display(), err),
            FileOpenError { what, path, err } => write!(f, "Failed to open {} file '{}': {}", what, path.display(), err),
            FileMetadataError { path, err } => write!(f, "Failed to read metadata of file '{}': {}", path.display(), err),
            FilePermissionsError { path, err } => write!(f, "Failed to update the permissions of file '{}': {}", path.display(), err),
            FileWriteError { what, path, err } => write!(f, "Failed to write to {} file '{}': {}", what, path.display(), err),
            FileCopyError { source, target, err } => write!(f, "Failed to copy file '{}' to '{}': {}", source.display(), target.display(), err),
            FileRemoveError { path, err } => write!(f, "Failed to remove file '{}': {}", path.display(), err),
            FileChecksumError { what, path, got, expected } => {
                write!(f, "Checksum of {} file '{}' is incorrect: expected '{}', got '{}'", what, path.display(), got, expected)
            },
            FileLockError { path, err } => write!(f, "Failed to lock file '{}': {}", path.display(), err),

            DirNotFound { path } => write!(f, "Directory '{}' not found", path.display()),
            DirNotADir { what, path } => write!(f, "{} directory '{}' exists but is not a directory", what.capitalize(), path.display()),
            DirCreateError { what, path, err } => write!(f, "Failed to create {} directory '{}': {}", what, path.display(), err),
            DirReadError { what, path, err } => write!(f, "Failed to read {} directory '{}': {}", what, path.display(), err),
            DirEntryReadError { what, path, entry, err } => {
                write!(f, "Failed to read entry {} from {} directory '{}': {}", entry, what, path.display(), err)
            },
            DirRemoveError { path, err } => write!(f, "Failed to remove directory '{}': {}", path.display(), err),
            DirNotOneEntry { what, path } => write!(f, "{} directory '{}' does not have exactly one entry", what.capitalize(), path.display()),
            DirNonDirChild { what, path, child } => {
                write!(f, "Entry '{}' in {} directory '{}' is not a directory", child.to_string_lossy(), what, path.display())
            },

            NotHttpsError { address } => {
                write!(f, "Security policy requires HTTPS is enabled, but '{address}' does not enable it (or we cannot parse the URL)")
            },
            RequestError { address, err } => write!(f, "Failed to send GET-request to '{address}': {err}"),
            RequestFailure { address, code, err } => write!(
                f,
                "GET-request to '{}' failed with status code {} ({}){}",
                address,
                code.as_u16(),
                code.canonical_reason().unwrap_or("???"),
                if let Some(err) = err { format!(": {err}") } else { String::new() }
            ),
            DownloadError { address, err } => write!(f, "Failed to download file '{address}': {err}"),

            EncoderFlushError { err } => write!(f, "Failed to flush GzipEncoder: {err}"),

            TarAppendError { source, tarball, err } => {
                write!(f, "Failed to append '{}' to tarball '{}': {}", source.display(), tarball.display(), err)
            },
            TarFinishError { path, err } => write!(f, "Failed to finish writing tarball '{}': {}", path.display(), err),
            TarEntriesError { path, err } => write!(f, "Failed to read entries in tarball '{}': {}", path.display(), err),
            TarEntryError { path, entry, err } => write!(f, "Failed to read entry {} in tarball '{}': {}", entry, path.display(), err),
            TarEntryPathError { path, entry, err } => write!(f, "Failed to get path of entry {} in tarball '{}': {}", entry, path.display(), err),
            TarExtractError { tarball, entry, target, err } => {
                write!(f, "Failed to extract '{}' in tarball '{}' to '{}': {}", entry.display(), tarball.display(), target.display(), err)
            },
        }
    }
}
impl std::error::Error for Error {}





/***** AUXILLARY *****/
/// Defines permission flags we can set per group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionFlags(u8);
impl PermissionFlags {
    /// All permissions are given (read, write, execute)
    pub const ALL: Self = Self(0b111);
    /// Represents execute permission.
    pub const EXECUTE: Self = Self(0b001);
    /// No permissions.
    pub const NONE: Self = Self(0b000);
    /// Represents read permission.
    pub const READ: Self = Self(0b100);
    /// Represents write permission.
    pub const WRITE: Self = Self(0b010);
}
impl BitAnd for PermissionFlags {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output { Self(self.0 & rhs.0) }
}
impl BitAndAssign for PermissionFlags {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) { self.0 &= rhs.0 }
}
impl BitOr for PermissionFlags {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output { Self(self.0 | rhs.0) }
}
impl BitOrAssign for PermissionFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0 }
}

/// Defines a set of permissions for the user, their group and others.
#[derive(Clone, Debug)]
pub struct PermissionSet {
    /// The permissions for the owning user.
    pub user:  PermissionFlags,
    /// The permissions for the owning group.
    pub group: PermissionFlags,
    /// The permissions for any other personage.
    pub other: PermissionFlags,
}
impl PermissionSet {
    /// Returns a binary representation of the internal permissions.
    #[cfg(unix)]
    #[inline]
    fn octets(&self) -> u32 { ((self.user.0 as u32) << 6) | ((self.group.0 as u32) << 3) | (self.other.0 as u32) }
}



/// Defines things to do to assert a downloaded file is secure and what we expect.
#[derive(Clone, Debug)]
pub struct DownloadSecurity<'c> {
    /// If not `None`, then it defined the checksum that the file should have.
    pub checksum: Option<&'c [u8]>,
    /// If true, then the file can only be downloaded over HTTPS.
    pub https:    bool,
}
impl<'c> DownloadSecurity<'c> {
    /// Constructor for the DownloadSecurity that enables with all security measures enabled.
    ///
    /// This will provide you with the most security, but is also the slowest method (since it does both encryption and checksum computation).
    ///
    /// Usually, it sufficies to only use a checksum (`DownloadSecurity::checksum()`) if you know what the file looks like a-priori.
    ///
    /// # Arguments
    /// - `checksum`: The checksum that we want the file to have. If you are unsure, give a garbage checksum, then run the function once and check what the file had (after making sure the download went correctly, of course).
    ///
    /// # Returns
    /// A new DownloadSecurity instance that will make your downloaded file so secure you can use it to store a country's defecit (not legal advice).
    #[inline]
    pub fn all(checkum: &'c [u8]) -> Self { Self { checksum: Some(checkum), https: true } }

    /// Constructor for the DownloadSecurity that enables checksum verification only.
    ///
    /// Using this method is considered secure, since it guarantees that the downloaded file is what we expect. It is thus safe to use if you don't trust either the network or the remote praty.
    ///
    /// Note, however, that this method only works if you know a-priori what the downloaded file should look like. If not, you must use another security method (e.g., `DownloadSecurity::https()`).
    ///
    /// # Arguments
    /// - `checksum`: The checksum that we want the file to have. If you are unsure, give a garbage checksum, then run the function once and check what the file had (after making sure the download went correctly, of course).
    ///
    /// # Returns
    /// A new DownloadSecurity instance that will make sure your file has the given checksum before returning.
    #[inline]
    pub fn checksum(checkum: &'c [u8]) -> Self { Self { checksum: Some(checkum), https: false } }

    /// Constructor for the DownloadSecurity that forces downloads to go over HTTPS.
    ///
    /// You should only use this method if you trust the remote party. However, if you do, then it guarantees that there was no man-in-the-middle changing the downloaded file.
    ///
    /// # Returns
    /// A new DownloadSecurity instance that will make sure your file if downloaded over HTTPS only.
    #[inline]
    pub fn https() -> Self { Self { checksum: None, https: true } }

    /// Constructor for the DownloadSecurity that disabled all security measures.
    ///
    /// For obvious reasons, this security is not recommended unless you trust both the network _and_ the remote party.
    ///
    /// # Returns
    /// A new DownloadSecurity instance that will require no additional security measures on the downloaded file.
    #[inline]
    pub fn none() -> Self { Self { checksum: None, https: false } }
}
impl Display for DownloadSecurity<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        // Write what is enabled
        if let Some(checksum) = &self.checksum {
            write!(f, "Checksum ({})", hex::encode(checksum))?;
            if self.https {
                write!(f, ", HTTPS")?;
            }
            Ok(())
        } else if self.https {
            write!(f, "HTTPS")
        } else {
            write!(f, "None")
        }
    }
}





/***** LIBRARY *****/
/// Defines a wrapper around a file handle that can be used to implement file locks.
#[derive(Debug)]
pub struct FileLock {
    /// The path to the file handle.
    path:    PathBuf,
    /// The file handle that represents the (unique!) lock.
    _handle: fs::File,
}
impl FileLock {
    /// Constructor for the FileLock that attempts to lock the given file.
    ///
    /// This function will block until it becomes available.
    ///
    /// Note that this lock is an exclusive lock.
    ///
    /// # Arguments
    /// - `name`: The name of the package for which we are waiting.
    /// - `version`: The version of the package for which we are waiting.
    /// - `path`: The path of the file to use a lockfile.
    ///
    /// # Returns
    /// A new instance of the FileLock that acts as a guard of the lock. As long as it's in scope, the exclusive lock will be held.
    pub fn lock(name: impl AsRef<str>, version: impl AsRef<Version>, path: impl Into<PathBuf>) -> Result<Self, Error> {
        let name: &str = name.as_ref();
        let version: &Version = version.as_ref();
        let path: PathBuf = path.into();

        // Attempt to get the file handle
        let handle: fs::File = match fs::File::create(&path) {
            Ok(handle) => handle,
            Err(err) => {
                return Err(Error::FileCreateError { what: "lock file", path, err });
            },
        };

        // Test if we have to lock it
        if let Err(err) = handle.try_lock_exclusive() {
            if err.kind() == std::io::ErrorKind::WouldBlock {
                // Re-try for real (this is the actually blocking operation)
                debug!("Waiting for lock on '{}'...", path.display());
                println!(
                    "Package {} (version {}) is already being built by another process; waiting until it completes...",
                    style(name).bold().cyan(),
                    style(version).bold()
                );
                if let Err(err) = handle.lock_exclusive() {
                    return Err(Error::FileLockError { path, err });
                }
            } else {
                return Err(Error::FileLockError { path, err });
            }
        };

        // OK, return ourselves
        debug!("Lock '{}' acquired", path.display());
        Ok(Self { path, _handle: handle })
    }

    /// Releases this file lock.
    ///
    /// This works by simply consuming ourself, forcing a drop.
    #[inline]
    pub fn release(self) {}
}
impl Drop for FileLock {
    fn drop(&mut self) {
        // Simply print we are unlocking it; dropping the internal handle will do the rest
        debug!("Lock '{}' released", self.path.display());
    }
}



/// Changes the permissions of the given file to the given triplet.
///
/// # Arguments
/// - `path`: The path of the file to change the permissions of.
/// - `permissions`: The `PermissionSet` to change to.
///
/// # Errors
/// This function errors if we failed to update the permissions - probably either because the file did not exist, or we do not have the required permisisons ourselves.
pub fn set_permissions(path: impl AsRef<Path>, permissions: PermissionSet) -> Result<(), Error> {
    let path: &Path = path.as_ref();
    debug!("Setting permissions for file '{}'...", path.display());

    // Read the current permissions from the given file.
    let mut perms: Permissions = match fs::metadata(path) {
        Ok(metadata) => metadata.permissions(),
        Err(err) => {
            return Err(Error::FileMetadataError { path: path.into(), err });
        },
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        // Overwrite the permissions
        perms.set_mode(permissions.octets());
    }
    #[cfg(windows)]
    {
        // On windows we can only do write permissions
        let new_readonly: bool = (permissions.user & PermissionFlags::WRITE) != PermissionFlags::WRITE;
        if perms.readonly() != new_readonly {
            debug!("Only changing user readonly permission for '{}' (write & executable not supported on windows)", path.display());
            perms.set_readonly(new_readonly);
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::compile_error!("Non-Unix, non-Windows OS not supported.");
    }

    // Write it back
    match fs::set_permissions(path, perms) {
        Ok(_) => Ok(()),
        Err(err) => Err(Error::FilePermissionsError { path: path.into(), err }),
    }
}

/// Updates the permissions of the given file to become executable.
///
/// # Arguments
/// - `path`: The path of the file to change the permissions of.
///
/// # Errors
/// This function errors if we failed to update the permissions - probably either because the file did not exist, or we do not have the required permisisons ourselves.
#[cfg(unix)]
pub fn set_executable(path: impl AsRef<Path>) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt as _;

    let path: &Path = path.as_ref();
    debug!("Making file '{}' executable...", path.display());

    // Read the current permissions from the given file.
    let mut perms: Permissions = match fs::metadata(path) {
        Ok(metadata) => metadata.permissions(),
        Err(err) => {
            return Err(Error::FileMetadataError { path: path.into(), err });
        },
    };

    // Overwrite the permissions
    perms.set_mode(
        perms.mode() | PermissionSet { user: PermissionFlags::EXECUTE, group: PermissionFlags::NONE, other: PermissionFlags::NONE }.octets(),
    );

    // Write it back
    match fs::set_permissions(path, perms) {
        Ok(_) => Ok(()),
        Err(err) => Err(Error::FilePermissionsError { path: path.into(), err }),
    }
}
/// Updates the permissions of the given file to become executable.
///
/// Note that this overload does not actually do anything, since Windows doesn't really have this notion of executable files.
///
/// # Arguments
/// - `path`: The path of the file to change the permissions of.
///
/// # Errors
/// This function errors if we failed to update the permissions - probably either because the file did not exist, or we do not have the required permisisons ourselves.
#[cfg(windows)]
pub fn set_executable(path: impl AsRef<Path>) -> Result<(), Error> {
    let path: &Path = path.as_ref();

    // Assert the file exists and that's all
    debug!("Nothing to do to make file '{}' executable (only file existance is checked)...", path.display());
    if !path.exists() {
        return Err(Error::PathNotFoundError { what: "file", path: path.into() });
    }
    Ok(())
}
#[cfg(not(any(unix, windows)))]
pub fn set_executable(path: impl AsRef<Path>) -> Result<(), Error> {
    std::compile_error!("Non-Unix, non-Windows OS not supported.");
}



/// Unwraps a folder into its only child folder.
///
/// # Arguments
/// - `dir`: The directory to recurse in.
///
/// # Returns
/// The path of the nested directory.
///
/// # Errors
/// This function may error if:
/// - The given `dir` is not a directory;
/// - It has another number than 1 entries; or
/// - That entry is not a directory.
pub async fn recurse_in_only_child_async(dir: impl AsRef<Path>) -> Result<PathBuf, Error> {
    let dir: &Path = dir.as_ref();
    debug!("Recursing into only directory child of '{}'...", dir.display());

    // Attempt to go thru the child's directories
    match tfs::read_dir(dir).await {
        Ok(mut entries) => {
            if let (Some(entry), None) = (entries.next_entry().await.transpose(), entries.next_entry().await.transpose()) {
                // Assert it's a directory
                match entry {
                    Ok(entry) => {
                        let path: PathBuf = entry.path();
                        if path.is_dir() {
                            Ok(path)
                        } else {
                            Err(Error::DirNonDirChild { what: "to-be-trivially-recursed", path: dir.into(), child: entry.file_name() })
                        }
                    },
                    Err(err) => Err(Error::DirEntryReadError { what: "to-be-trivially-recursed", path: dir.into(), entry: 0, err }),
                }
            } else {
                Err(Error::DirNotOneEntry { what: "to-be-trivially-recursed", path: dir.into() })
            }
        },
        Err(err) => Err(Error::DirReadError { what: "to-be-trivially-recursed", path: dir.into(), err }),
    }
}



/// Moves the given or directory from one location to another.
///
/// If possible, it will attempt to use the efficient `rename()`; otherwise, it will perform te extensive copy.
///
/// # Arguments
/// - `source`: The current, existing file or directory to copy.
/// - `target`: The target, non-existing location where the directory will be copied to.
///
/// # Errors
/// This function errors if we failed to read or write anything or if some directories do or do not exist.
pub async fn move_path_async(source: impl AsRef<Path>, target: impl AsRef<Path>) -> Result<(), Error> {
    let source: &Path = source.as_ref();
    let target: &Path = target.as_ref();
    debug!("Moving '{}' to '{}'...", source.display(), target.display());

    // TODO: As soon as the feature below becomes stable, which appears to be very soon, we can uncomment this to have the cheap one first :)
    // // Attempt to use the cheap command
    // match tfs::rename(source, target).await {
    //     Ok(_)    => { return Ok(()); },
    //     Err(err) => if err.kind() != std::io::ErrorKind::CrossesDevices { return Err(Error::PathRenameError{ source: source.into(), target: target.into(), err }); },
    // }

    // That failed; do the expensive one by first copying...
    if source.is_file() {
        if let Err(err) = tfs::copy(source, target).await {
            return Err(Error::FileCopyError { source: source.into(), target: target.into(), err });
        }
    } else {
        copy_dir_recursively_async(source, target).await?;
    }

    // Then remove the old one
    if source.is_file() {
        tfs::remove_file(source).await.map_err(|err| Error::FileRemoveError { path: source.into(), err })?;
    } else {
        tfs::remove_dir_all(source).await.map_err(|err| Error::DirRemoveError { path: source.into(), err })?;
    }

    // And we're done!
    Ok(())
}

/// Recursively copies the given directory using tokio's async library.
///
/// # Arguments
/// - `source`: The current, existing directory to copy.
/// - `target`: The target, non-existing location where the directory will be copied to.
///
/// # Errors
/// This function errors if we failed to read or write anything or if some directories do or do not exist.
pub async fn copy_dir_recursively_async(source: impl AsRef<Path>, target: impl AsRef<Path>) -> Result<(), Error> {
    let source: &Path = source.as_ref();
    let target: &Path = target.as_ref();
    debug!("Copying directory '{}' to '{}'...", source.display(), target.display());

    // Create the dst_path directory if it doesn't exist already
    if !target.is_dir() {
        if target.exists() {
            return Err(Error::DirNotADir { what: "target", path: target.into() });
        }
        if let Err(err) = tfs::create_dir(target).await {
            return Err(Error::DirCreateError { what: "target", path: target.into(), err });
        }
    }

    // Start reading the directory
    let entries: tfs::ReadDir = match tfs::read_dir(source).await {
        Ok(entries) => entries,
        Err(err) => {
            return Err(Error::DirReadError { what: "source", path: source.into(), err });
        },
    };

    // We do non-function recursion to support very large directories
    let mut todo: Vec<(PathBuf, PathBuf, tfs::ReadDir)> = vec![(source.into(), target.into(), entries)];
    while let Some((cur_dir, dst_dir, mut entries)) = todo.pop() {
        // Iterate over the entries
        let mut i: usize = 0;
        #[allow(irrefutable_let_patterns)]
        while let e = entries.next_entry().await {
            // Unwrap the entry
            let e: tfs::DirEntry = match e {
                Ok(Some(e)) => e,
                Ok(None) => {
                    break;
                },
                Err(err) => {
                    return Err(Error::DirEntryReadError { what: "source", path: cur_dir, entry: i, err });
                },
            };

            // Switch on it being either a file or directory
            let e_path: PathBuf = e.path();
            if e_path.is_file() {
                // Copy the file over
                let dst_file: PathBuf = dst_dir.join(e_path.file_name().unwrap());
                debug!("Copying file '{}' to '{}'...", e_path.display(), dst_file.display());
                if let Err(err) = tfs::copy(&e_path, &dst_file).await {
                    return Err(Error::FileCopyError { source: e_path, target: dst_file, err });
                }
            } else if e_path.is_dir() {
                // Create the new directory
                let dir_path: PathBuf = dst_dir.join(e_path.file_name().unwrap());
                if let Err(err) = tfs::create_dir(&dir_path).await {
                    return Err(Error::DirCreateError { what: "nested target", path: dir_path, err });
                }

                // Mark the entries in this directory as todo, with the newly created directory as target
                let entries: tfs::ReadDir = match tfs::read_dir(&e_path).await {
                    Ok(entries) => entries,
                    Err(err) => {
                        return Err(Error::DirReadError { what: "nested source", path: e_path, err });
                    },
                };
                todo.push((e_path, dir_path, entries));
            } else {
                warn!("Path '{}' is neither a file nor a directory; skipping...", e_path.display());
            }

            // Don't forget to increment i
            i += 1;
        }
    }

    // Done with recursion? Done with copying
    Ok(())
}



/// Downloads some file from the interwebs to the given location.
///
/// # Arguments
/// - `source`: The URL to download the file from.
/// - `target`: The location to download the file to.
/// - `verification`: Some method to verify the file is what we think it is. See the `VerifyMethod`-enum for more information.
/// - `verbose`: If not `None`, will print to the output with accents given in the given `Style` (use a non-exciting Style to print without styles).
///
/// # Returns
/// Nothing, except that when it does you can assume a file exists at the given location.
///
/// # Errors
/// This function may error if we failed to download the file or write it (which may happen if the parent directory of `local` does not exist, among other things).
pub async fn download_file_async(
    source: impl AsRef<str>,
    target: impl AsRef<Path>,
    security: DownloadSecurity<'_>,
    verbose: Option<Style>,
) -> Result<(), Error> {
    let source: &str = source.as_ref();
    let target: &Path = target.as_ref();
    debug!("Downloading '{}' to '{}' (Security: {})...", source, target.display(), security);
    if let Some(style) = &verbose {
        println!("Downloading {}...", style.apply_to(source));
    }

    // Assert the download directory exists
    if let Some(parent) = target.parent() {
        if !parent.exists() {
            return Err(Error::DirNotFound { path: parent.into() });
        }
    }

    // Open the target file for writing
    let mut handle: tfs::File = match tfs::File::create(target).await {
        // Ok(handle) => {
        //     // Prepare the permissions to set by reading the file's metadata
        //     let mut permissions: Permissions = match handle.metadata() {
        //         Ok(metadata) => metadata.permissions(),
        //         Err(err)     => { return Err(Error::FileMetadataError{ what: "temporary binary", path: local.into(), err }); },
        //     };
        //     permissions.set_mode(permissions.mode() | 0o100);

        //     // Set them
        //     if let Err(err) = handle.set_permissions(permissions) { return Err(Error::FilePermissionsError{ what: "temporary binary", path: local.into(), err }); }

        //     // Return the handle
        //     handle
        // },
        Ok(handle) => handle,
        Err(err) => {
            return Err(Error::FileCreateError { what: "downloaded", path: target.into(), err });
        },
    };

    // Send a request
    let res: Response = if security.https {
        debug!("Sending download request to '{}' (HTTPS enabled)...", source);

        // Assert the address starts with HTTPS first
        if Url::parse(source).ok().map(|u| u.scheme() != "https").unwrap_or(true) {
            return Err(Error::NotHttpsError { address: source.into() });
        }

        // Send the request with a user-agent header (to make GitHub happy)
        let client: Client = Client::new();
        let req: Request = match client.get(source).header("User-Agent", "reqwest").build() {
            Ok(req) => req,
            Err(err) => {
                return Err(Error::RequestError { address: source.into(), err });
            },
        };
        match client.execute(req).await {
            Ok(req) => req,
            Err(err) => {
                return Err(Error::RequestError { address: source.into(), err });
            },
        }
    } else {
        debug!("Sending download request to '{}'...", source);

        // Send the request with a user-agent header (to make GitHub happy)
        let client: Client = Client::new();
        let req: Request = match client.get(source).header("User-Agent", "reqwest").build() {
            Ok(req) => req,
            Err(err) => {
                return Err(Error::RequestError { address: source.into(), err });
            },
        };
        match client.execute(req).await {
            Ok(req) => req,
            Err(err) => {
                return Err(Error::RequestError { address: source.into(), err });
            },
        }
    };

    // Assert it succeeded
    if !res.status().is_success() {
        return Err(Error::RequestFailure { address: source.into(), code: res.status(), err: res.text().await.ok() });
    }

    // Create the progress bar based on whether if there is a length
    debug!("Downloading response to file '{}'...", target.display());
    let len: Option<u64> = res.headers().get("Content-Length").and_then(|len| len.to_str().ok()).and_then(|len| u64::from_str(len).ok());
    let prgs: Option<ProgressBar> = if verbose.is_some() {
        Some(if let Some(len) = len {
            ProgressBar::new(len)
                .with_style(ProgressStyle::with_template("    {bar:60} {bytes}/{total_bytes} {bytes_per_sec} ETA {eta_precise}").unwrap())
        } else {
            ProgressBar::new_spinner()
                .with_style(ProgressStyle::with_template("    {elapsed_precise} {bar:60} {bytes} {binary_bytes_per_sec}").unwrap())
        })
    } else {
        None
    };

    // Prepare getting a checksum if that is our method of choice
    let mut hasher: Option<Sha256> = if security.checksum.is_some() { Some(Sha256::new()) } else { None };

    // Download the response to the opened output file
    let mut stream = res.bytes_stream();
    while let Some(next) = stream.next().await {
        // Unwrap the result
        let next = match next {
            Ok(next) => next,
            Err(err) => {
                return Err(Error::DownloadError { address: source.into(), err });
            },
        };

        // Write it to the file
        if let Err(err) = handle.write(&next).await {
            return Err(Error::FileWriteError { what: "downloaded", path: target.into(), err });
        }

        // If desired, update the hash
        if let Some(hasher) = &mut hasher {
            hasher.update(&*next);
        }

        // Update what we've written if needed
        if let Some(prgs) = &prgs {
            prgs.update(|state| state.set_pos(state.pos() + next.len() as u64));
        }
    }
    if let Some(prgs) = &prgs {
        prgs.finish_and_clear();
    }

    // Assert the checksums are the same if we're doing that
    if let Some(checksum) = security.checksum {
        // Finalize the hasher first
        let result = hasher.unwrap().finalize();
        debug!("Verifying checksum...");

        // Assert the checksums check out (wheezes)
        if &result[..] != checksum {
            return Err(Error::FileChecksumError {
                what:     "downloaded",
                path:     target.into(),
                expected: hex::encode(checksum),
                got:      hex::encode(&result[..]),
            });
        }

        // Print that the checksums are equal if asked
        if let Some(style) = verbose {
            // Create the dim styles
            let dim: Style = Style::new().dim();
            let accent: Style = style.dim();

            // Write it with those styles
            println!("{}{}{}", dim.apply_to(" > Checksum "), accent.apply_to(hex::encode(&result[..])), dim.apply_to(" OK"));
        }
    }

    // Done
    Ok(())
}



/// Archives the given file or directory as a `.tar.gz` file.
///
/// # Arguments
/// - `source`: The source file or directory to archive.
/// - `tarball`: The target tarball file to archive to.
/// - `skip_root_dir`: If the `source` points to a directory, then this determines whether to trim it (true) or not (false) in the resulting tarfile
///   (i.e., the files in the root dir will be in the tar's root instead of the directory). Ignore otherwise.
///
/// # Errors
/// This function errors if we somehow encountered an error.
pub async fn archive_async(source: impl AsRef<Path>, tarball: impl AsRef<Path>, skip_root_dir: bool) -> Result<(), Error> {
    let source: &Path = source.as_ref();
    let tarball: &Path = tarball.as_ref();
    debug!("Archiving '{}' to '{}'...", source.display(), tarball.display());

    // Open the target file
    let handle: tfs::File = match tfs::File::create(tarball).await {
        Ok(handle) => handle,
        Err(err) => {
            return Err(Error::FileCreateError { what: "target tarball", path: tarball.into(), err });
        },
    };

    // Create the encoder & tarfile around this file
    let enc: GzipEncoder<_> = GzipEncoder::new(handle);
    let mut tar: Builder<GzipEncoder<_>> = Builder::new(enc);

    // Now add the source recursively
    let mut is_root_dir: bool = true;
    let mut todo: Vec<(PathBuf, OsString)> = vec![(source.into(), source.file_name().map(|f| f.into()).unwrap_or_else(|| OsString::from(".")))];
    while let Some((path, name)) = todo.pop() {
        // Switch on the file type
        if path.is_file() {
            debug!("Adding file '{}' as '{}/{}'...", path.display(), tarball.display(), name.to_string_lossy());

            // Compress as a file
            if let Err(err) = tar.append_path_with_name(&path, name).await {
                return Err(Error::TarAppendError { source: path, tarball: tarball.into(), err });
            }
        } else if path.is_dir() {
            // Recurse to add the files
            let mut entries: tfs::ReadDir = match tfs::read_dir(&path).await {
                Ok(entries) => entries,
                Err(err) => {
                    return Err(Error::DirReadError { what: "nested source", path, err });
                },
            };
            let mut i: usize = 0;
            loop {
                // Fetch the next entry
                let entry: tfs::DirEntry = match entries.next_entry().await {
                    Ok(Some(entry)) => entry,
                    Ok(None) => {
                        break;
                    },
                    Err(err) => {
                        return Err(Error::DirEntryReadError { what: "nested source", path, entry: i, err });
                    },
                };
                i += 1;

                // Compute the tar-side path of this file
                let name: &OsStr = if skip_root_dir && is_root_dir { OsStr::new("") } else { &name };

                // Add its path
                todo.push((entry.path(), PathBuf::from(name).join(entry.file_name()).into()));
            }
            is_root_dir = false;
        } else if !path.exists() {
            return Err(Error::PathNotFoundError { what: "nested source", path });
        } else {
            return Err(Error::PathNotFileNotDir { what: "nested source", path });
        }
    }

    // Finish writing the archive
    debug!("Finishing tarball...");
    match tar.into_inner().await {
        Ok(mut enc) => {
            // Flush the encoder before we quit
            if let Err(err) = enc.shutdown().await {
                return Err(Error::EncoderFlushError { err });
            };
            Ok(())
        },
        Err(err) => Err(Error::TarFinishError { path: tarball.into(), err }),
    }
}

/// Unarchives the given `.tar.gz` file to the given location.
///
/// # Arguments
/// - `tarball`: The source tarball file to extract from.
/// - `target`: The target directory to write to. Note that we will throw all sorts of nasty errors if it already exists somehow.
///
/// # Errors
/// This function errors if we failed to read or write anything or if some directories do or do not exist.
pub async fn unarchive_async(tarball: impl AsRef<Path>, target: impl AsRef<Path>) -> Result<(), Error> {
    let tarball: &Path = tarball.as_ref();
    let target: &Path = target.as_ref();
    debug!("Extracting '{}' to '{}'...", tarball.display(), target.display());

    // Whine if the target already exists
    if target.exists() {
        return Err(Error::PathExistsError { what: "target", path: target.into() });
    }
    if let Err(err) = tfs::create_dir(target).await {
        return Err(Error::DirCreateError { what: "target", path: target.into(), err });
    }

    // Open the source tarfile
    let handle: tfs::File = match tfs::File::open(tarball).await {
        Ok(handle) => handle,
        Err(err) => {
            return Err(Error::FileOpenError { what: "source tarball", path: tarball.into(), err });
        },
    };

    // Create the decoder & tarfile around this file
    let dec: GzipDecoder<_> = GzipDecoder::new(tio::BufReader::new(handle));
    let mut tar: Archive<GzipDecoder<_>> = Archive::new(dec);
    let mut entries: Entries<GzipDecoder<_>> = match tar.entries() {
        Ok(entries) => entries,
        Err(err) => {
            return Err(Error::TarEntriesError { path: tarball.into(), err });
        },
    };

    // Iterate over all of the entries
    let mut i: usize = 0;
    while let Some(entry) = entries.next().await {
        // Unwrap the entry
        // let mut entry: Entry<Archive<GzipDecoder<_>>> = match entry {
        let mut entry: Entry<Archive<_>> = match entry {
            Ok(entry) => entry,
            Err(err) => {
                return Err(Error::TarEntryError { path: tarball.into(), entry: i, err });
            },
        };
        i += 1;

        // Attempt to extract the entry
        let entry_path: PathBuf = match entry.path() {
            Ok(entry_path) => entry_path.into(),
            Err(err) => {
                return Err(Error::TarEntryPathError { path: tarball.into(), entry: i, err });
            },
        };

        // Unpack the thing
        let target_path: PathBuf = target.join(&entry_path);
        debug!("Extracting '{}/{}' to '{}'...", tarball.display(), entry_path.display(), target_path.display());
        match entry.unpack_in(&target).await {
            Ok(true) => {},
            Ok(false) => {
                return Err(Error::PathWithParentDir { what: "nested target", path: target_path });
            },
            Err(err) => {
                return Err(Error::TarExtractError { tarball: tarball.into(), entry: entry_path, target: target_path, err });
            },
        }

        // Done, go to next entry
    }

    // Done
    Ok(())
}
