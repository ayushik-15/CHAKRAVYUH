# CHAKRAVYUH

# CHAKRAVYUH

**Hack in Hills '26 - Top 500 Prototype Submission**

CHAKRAVYUH is an AI safety red-teaming platform designed with a Commit-Reveal Evaluation Protocol (CREP). The system evaluates attack strategies (Red Plane) and defense mechanisms (Blue Plane) through a real-time Arbiter Hub and maintains a cryptographically signed Merkle transparency log.

**Future Scope Note:** This current prototype focuses entirely on the evaluation protocol and real-time dashboard. Predictive maintenance features are strictly reserved for future development phases and are not included in this build.

**Tech Stack**
* **Frontend:** React 19, Vite, Tailwind CSS v4, Lucide-react
* **Backend:** FastAPI, Python, WebSockets

**Local Setup Instructions**

**1. Start the Arbiter Backend**
Open a terminal and navigate to the backend directory:
`cd arbiter`
Install dependencies and run the server:
`pip install -r requirements.txt` (or `pip install fastapi uvicorn websockets`)
`python -m uvicorn main:app --reload --port 8000`

**2. Start the Frontend Dashboard**
Open a second terminal and navigate to the frontend directory:
`cd frontend`
Install dependencies and run the development server:
`npm install`
`npm run dev`

The real-time dashboard will be accessible at `http://localhost:5173` with an active Arbiter Hub connection.