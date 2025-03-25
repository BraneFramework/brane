/* HEALTH.rs
 *   by Lut99
 *
 * Created:
 *   12 Jan 2022, 13:29:01
 * Last edited:
 *   08 May 2022, 14:40:04
 * Auto updated?
 *   Yes
 *
 * Description:
 *   Contains code for the health part of the brane API.
**/

use warp::http::HeaderValue;
use warp::hyper::Body;
use warp::reply::Response;
use warp::{Rejection, Reply};


pub async fn handle() -> Result<impl Reply, Rejection> {
    let mut response = Response::new(Body::from("OK!\n"));

    response.headers_mut().insert("Content-Length", HeaderValue::from(4));

    Ok(response)
}
