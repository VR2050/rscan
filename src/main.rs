
use rscan::cli;

#[tokio::main]
async fn main() {
    if let Err(e) = cli::run().await {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }
}


#[cfg(test)]
pub mod tests{
    use super::*;
    #[test]
   //测试主机扫描引擎
    fn test_netscan_engine(){
         let target ="192.168.128.56";
         let ports="22,80,443,8080";
            println!("测试主机扫描引擎，目标主机：{}，端口：{}",target,ports);
            let s=rscan::cores::netscan_en::manager::ScanManager::default();
            

    }  

     
}