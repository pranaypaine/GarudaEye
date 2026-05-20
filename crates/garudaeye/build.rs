use std::process::Command;
use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=../../frontend");
    
    // Build frontend if Node.js is available
    let frontend_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("frontend");
    
    if frontend_dir.exists() {
        println!("Building frontend at {:?}", frontend_dir);
        
        // Check if npm/node is available
        if which::which("npm").is_ok() {
            // Install dependencies if node_modules doesn't exist
            let node_modules = frontend_dir.join("node_modules");
            if !node_modules.exists() {
                println!("Installing frontend dependencies...");
                let status = Command::new("npm")
                    .arg("install")
                    .current_dir(&frontend_dir)
                    .status()
                    .expect("Failed to run npm install");
                
                if !status.success() {
                    panic!("npm install failed");
                }
            }
            
            // Build frontend
            println!("Building frontend assets...");
            let status = Command::new("npm")
                .arg("run")
                .arg("build")
                .current_dir(&frontend_dir)
                .status()
                .expect("Failed to run npm build");
            
            if !status.success() {
                panic!("npm build failed");
            }
            
            println!("Frontend build complete");
        } else {
            println!("cargo:warning=npm not found, skipping frontend build");
        }
    } else {
        println!("cargo:warning=Frontend directory not found at {:?}", frontend_dir);
    }
}
