// const API_URL = 'http://127.0.0.1:5000';

// function register_user() {
//     const username = document.getElementById("username").value;
//     if (!username) return alert("Please enter a username.");

//     fetch(`${API_URL}/user/register`, {
//         method: "POST",
//         headers: {
//             "Content-Type": "application/json"
//         },
//         body: JSON.stringify({ username })
//     })
//     .then(response => response.json())
//     .then(data => {
//         if (data.public_key) {
//             alert("User registered successfully!");
//         } else {
//             alert("Error: " + data.error);
//         }
//     })
//     .catch(error => console.error("Error:", error));
// }


const API_URL = 'http://127.0.0.1:5000'; // Backend Flask server URL

// Register a new user
function register_user() {
    const username = document.getElementById("username").value;
    if (!username) return alert("Please enter a username.");

    fetch("http://127.0.0.1:5000/user/register", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ username })
    })
    .then(response => response.json())
    .then(data => {
        console.log(data);
        if (data.public_key) {
            alert("User registered successfully!");
            window.location.href = "add_funds.html";
        } else {
            alert("Error: " + data.error);
        }
    })
    .catch(error => {
        console.error("Error:", error);
    });
}

// Add funds to a user account
async function add_funds() {
    const username = document.getElementById('add_funds_username').value;
    const amount = document.getElementById('add_funds_amount').value;
    if (!username || !amount) return alert("Please fill out all fields.");

    const data = { username, amount: parseFloat(amount) };

    try {
        const response = await fetch("http://127.0.0.1:5000/add_funds", {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        const result = await response.json();
        
        console.log("Received response:", result); // Check response structure
        
        if (response.ok && result.success !== false) {
            alert(result.message);
            window.location.href = 'sign_transaction.html';
        } else {
            alert("Error: " + (result.error || "Unable to add funds."));
        }

    } catch (error) {
        console.error("Fetch error:", error);
        alert("An error occurred while adding funds.");
    }
}


// Sign a transaction

async function signTransaction() {
    const username = document.getElementById('sign_username').value.trim();
    const amount = parseFloat(document.getElementById('amount').value);

    if (!username || isNaN(amount)) {
        alert('Please enter a valid username and amount');
        return;
    }

    // Fetch and verify the balance before proceeding
    try {
        const balanceResponse = await fetch(`${API_URL}/balance/${username}`);
        const balanceData = await balanceResponse.json();

        console.log('Raw balance data:', balanceData);
        const userBalance = parseFloat(balanceData.balance);
        console.log(`Balance for ${username}: ${userBalance}`);

        if (isNaN(userBalance)) {
            return alert("Error: Balance data is not a valid number.");
        }

        if (userBalance < amount) {
            return alert("Insufficient balance to complete this transaction.");
        }

        // Proceed to sign the transaction if balance is sufficient
        const response = await fetch(`${API_URL}/user/sign`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, amount })
        });

        const data = await response.json();
        if (response.ok) {
            alert(`Transaction signed successfully! Signature: ${data.signature}`);
            // Display the signature and show the copy button
            document.getElementById('signatureOutput').innerText = data.signature;
            document.getElementById('signatureContainer').style.display = 'block';
        } else {
            alert(`Error: ${data.error}`);
            document.getElementById('signatureOutput').innerText = `Error: ${data.error}`;
        }
    } catch (error) {
        console.error('Unexpected error while checking balance or signing transaction:', error);
        alert('An unexpected error occurred. Please try again later.');
    }
}

// Function to copy the signature to the clipboard
function copySignature() {
    const signatureText = document.getElementById('signatureOutput').innerText;
    navigator.clipboard.writeText(signatureText)
        .then(() => {
            alert('Signature copied to clipboard!');
            window.location.href="create_transaction.html"
        })
        .catch(err => {
            console.error('Failed to copy signature: ', err);
            alert('Failed to copy signature. Please try again.');
        });
}


// Create a new transaction
async function create_transaction() {
    console.log("Create transaction function called.");

    const sender = document.getElementById('transaction_sender').value;
    const recipient = document.getElementById('transaction_recipient').value;
    const amount = document.getElementById('transaction_amount').value;
    const signature = document.getElementById('transaction_signature').value; 

    // Check for empty fields
    if (!sender || !recipient || !amount || !signature) {
        console.error("Empty fields detected.");
        return alert("Please fill out all fields, including the signature.");
    }

    // Check balance first
    try {
        const balanceResponse = await fetch(`${API_URL}/balance/${sender}`);
        const balanceData = await balanceResponse.json();
        console.log("Fetched balance data:", balanceData); // Log the balance data

        if (balanceData.balance < amount) {
            console.error("Insufficient balance:", balanceData.balance, amount);
            return alert("Insufficient balance to complete this transaction.");
        }
    } catch (error) {
        console.error("Error fetching balance:", error);
        return alert("Error checking balance. Please try again.");
    }

    const data = {
        sender,
        recipient,
        amount: parseFloat(amount),
        signature 
    };

    try {
        const transactionResponse = await fetch(`${API_URL}/transactions/new`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });

        const result = await transactionResponse.json();
        console.log("Transaction result:", result); // Log the transaction result

        // Assuming that a successful transaction will have a specific structure
        if (result && result.message && result.message.includes('will be added to Block')) {
            alert('Transaction submitted successfully! It will be added to the blockchain.');
            window.location.href="mine_block.html";
        } else {
            console.error('Transaction failed:', result.message);
            alert(`Transaction failed: ${result.message || 'Unknown error'}`);
        }
    } catch (error) {
        console.error("Error creating transaction:", error);
        alert("Error creating transaction. Please try again.");
    }
}



// Mine a new block
async function mine_block() {
    try {
        const response = await fetch(`${API_URL}/mine`);
        const result = await response.json();
        document.getElementById('output').innerText = JSON.stringify(result, null, 2);
    } catch (error) {
        console.error(error);
    }
}

// Fetch the blockchain when "Chain" button is clicked
async function fetchChain() {
    try {
        const response = await fetch(`${API_URL}/chain`);
        if (!response.ok) throw new Error("Network response was not ok");
        const result = await response.json();
        document.getElementById('chain_output').innerText = JSON.stringify(result, null, 2);
    } catch (error) {
        console.error("Error fetching chain:", error);
        alert("Error fetching chain. Please try again.");
    }
}

// Check user balance
async function check_balance() {
    const username = document.getElementById('balance_username').value;
    if (!username) return alert("Please enter a username.");

    try {
        const response = await fetch(`${API_URL}/balance/${username}`);
        if (!response.ok) throw new Error("Network response was not ok");
        const result = await response.json();
        document.getElementById('output').innerText = `Balance for ${username}: ${result.balance}`;
    } catch (error) {
        console.error("Error fetching balance:", error);
        alert("Error fetching balance. Please try again.");
    }
}
