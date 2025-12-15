use reqwest::{Client,Response,Request};
#[derive(Debug)]
pub struct Crawl{
    pub client:Client,
    pub req:Request,
    pub resp:Response,
}

impl Crawl{
    pub fn new(client:Client,req:Request,resp:Response)->Self{
        Crawl{
            client,
            req,
            resp,
        }
    }
    
}
