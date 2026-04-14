import { exec } from "child_process";

const analyzeDisk = (filePath) => {
  return new Promise((resolve, reject) => {
    
    const command = `fls -r ${filePath}`;

    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject(error.message);
      } else {
        const lines = stdout.split("\n");

        const results = lines.map((line) => {
          return {
            type: "File Entry",
            line: line,
          };
        });

        resolve(results);
      }
    });
  });
};

export default analyzeDisk;