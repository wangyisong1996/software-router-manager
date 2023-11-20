const child_process = require("child_process");

const system = (cmd) => {
    console.log(`Running: ${cmd}`);
    return new Promise((resolve, reject) => {
        child_process.exec(cmd, (err, stdout, stderr) => {
            if (err) {
                reject(err);
            } else {
                resolve({ stdout, stderr });
            }
        });
    });
};

module.exports = {
    system,
};
