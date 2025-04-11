//  VERSION.rs
//    by Lut99
//
//  Created:
//    26 Sep 2022, 15:39:41
//  Last edited:
//    26 Sep 2022, 15:58:37
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the function(s) that handle the `/version` path(s).
//

use tracing::debug;
use warp::http::HeaderValue;
use warp::hyper::Body;
use warp::reply::Response;
use warp::{Rejection, Reply};


/***** LIBRARY *****/
/// Handles a GET on the main `/version` path, returning the version number of this service.
///
/// # Returns
/// The response that can be send back to the client. Simply contains the string 'vXX.YY.ZZ', where
/// - `XX` is the major version;
/// - `YY` is the minor version; and
/// - `ZZ` is the patch version.
///
/// # Errors
/// This function doesn't usually error.
pub async fn get() -> Result<impl Reply, Rejection> {
    debug!("Handling GET on `/version` (i.e., get service version)...");

    // Parse Cargo's version number
    let version = env!("CARGO_PKG_VERSION");
    let version = format!("v{version}");
    let version_len = version.len();

    // Construct a response with the body and the content-length header
    let mut response = Response::new(Body::from(version));
    response.headers_mut().insert("Content-Length", HeaderValue::from(version_len));

    // Done
    Ok(response)
}
