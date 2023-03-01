/* VERSION.rs
 *   by Lut99
 *
 * Created:
 *   08 May 2022, 14:38:11
 * Last edited:
 *   08 May 2022, 14:42:38
 * Auto updated?
 *   Yes
 *
 * Description:
 *   Handles the /version path from in the API.
**/

use warp::reply::Response;
use warp::http::HeaderValue;
use warp::hyper::Body;
use warp::{Reply, Rejection};


/***** HANDLER *****/
/// Handles the '/version' path.
/// 
/// Simply returns the environment veriable with '200 OK'.
pub async fn handle() -> Result<impl Reply, Rejection> {
    let version = env!("CARGO_PKG_VERSION");
    let version = format!("v{version}");
    let version_len = version.len();
    let mut response = Response::new(Body::from(version));

    response.headers_mut().insert(
        "Content-Length",
        HeaderValue::from(version_len),
    );

    Ok(response)
}
