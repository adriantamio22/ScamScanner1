import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyBrZIvBrlCUqZZ7t0AtKnNTpd70q_erOs8",
  authDomain: "scamscanner2-fec52.firebaseapp.com",
  projectId: "scamscanner2-fec52",
  storageBucket: "scamscanner2-fec52.firebasestorage.app",
  messagingSenderId: "850048239545",
  appId: "1:850048239545:web:b47ad64b89102ba2241868"
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);
export const googleProvider = new GoogleAuthProvider();
