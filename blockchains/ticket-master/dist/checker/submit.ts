import {compile} from '@ton/blueprint';
import axios from 'axios';

async function main() {
    const baseUrl = process.argv[2] || 'http://localhost:3000';
    const submitUrl = new URL('/submit', baseUrl).toString();

    try {
        console.log('Compiling exploit contract...');
        const exploitCode = await compile('Exploit');
        const exploitCodeBase64 = exploitCode.toBoc().toString('base64');
        
        console.log('Submitting to server...');
        const response = await axios.post(submitUrl, {
            code: exploitCodeBase64,
            steps: 5
        });
        
        console.log('Server response:', response.data);
    } catch (error) {
        if (axios.isAxiosError(error)) {
            console.error('Error submitting to server:', error.response?.data || error.message);
        } else {
            console.error('Error:', error);
        }
    }
}

main();
