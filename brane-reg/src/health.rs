//  HEALTH.rs
//    by Lut99
//
//  Created:
//    26 Sep 2022, 15:41:12
//  Last edited:
//    26 Sep 2022, 15:59:07
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements function(s) that handle various REST function(s) on the
//!   `/health` path(s).
//

use tracing::debug;
use warp::http::HeaderValue;
use warp::hyper::Body;
use warp::reply::Response;
use warp::{Rejection, Reply};


/***** LIBRARY *****/
/// Handles a GET on the main `/health` path, returning that this service is alive.
///
/// # Returns
/// The response that can be send back to the client. Simply contains the string "OK!\n".
///
/// # Errors
/// This function doesn't usually error.
pub async fn get() -> Result<impl Reply, Rejection> {
    debug!("Handling GET on `/health` (i.e., confirming service is alive)...");

    // Construct a response with the body and the content-length header
    let mut response = Response::new(Body::from("OK!\n"));
    response.headers_mut().insert("Content-Length", HeaderValue::from(4));

    // Done
    Ok(response)
}
