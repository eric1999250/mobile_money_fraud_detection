import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Wallet, Send, History, Lock, User, Camera, Check, RefreshCw, LogOut, AlertTriangle, Shield, Activity, Plane } from 'lucide-react';
import { fmtRWF, fmtDate, showAlert, setLoading } from '../utils/helpers';

const API = 'http://localhost:5000';
const TOKEN = () => localStorage.getItem('session_token');

const NavItem = ({ page, activePage, setActivePage, icon: Icon, label }) => (
  <button
    onClick={() => setActivePage(page)}
    className={`flex items-center gap-2.5 px-3.5 py-2.5 rounded-lg text-xs font-semibold transition-all w-full text-left font-sans relative ${
      activePage === page
        ? 'bg-emerald-500/10 text-emerald-500'
        : 'text-slate-500 hover:bg-slate-100 hover:text-slate-900'
    }`}
  >
    <Icon className="w-4 h-4 flex-shrink-0" />
    {label}
  </button>
);

const Card = ({ children, className = '' }) => (
  <div className={`bg-white border-2 border-slate-300 rounded-2xl mb-6 shadow-lg overflow-hidden ${className}`}>{children}</div>
);

const Button = ({ children, variant = 'primary', className = '', ...props }) => {
  const variants = {
    primary: 'bg-gradient-to-br from-emerald-500 to-sky-500 text-white hover:shadow-lg hover:-translate-y-0.5',
    ghost: 'bg-transparent text-slate-500 border border-slate-300 hover:bg-slate-100 hover:text-slate-900'
  };
  return (
    <button
      className={`px-4 py-2.5 rounded-lg font-semibold text-xs transition-all font-sans inline-flex items-center gap-1.5 ${variants[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
};

const AlertMsg = ({ msg }) => (
  msg.show ? (
    <div className={`p-2.5 rounded-lg text-xs mb-4 ${
      msg.type === 'success' ? 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20' :
      msg.type === 'error' ? 'bg-rose-500/10 text-rose-500 border border-rose-500/20' :
      'bg-sky-500/10 text-sky-500 border border-sky-500/20'
    }`}>
      {msg.message}
    </div>
  ) : null
);

export default function UserDashboard() {
  const navigate = useNavigate();
  const [activePage, setActivePage] = useState('balance');
  const [currentUser, setCurrentUser] = useState(null);
  const [balance, setBalance] = useState(0);
  const [transactions, setTransactions] = useState([]);
  const [history, setHistory] = useState([]);
  
  // Transfer state
  const [recipientPhone, setRecipientPhone] = useState('');
  const [recipientName, setRecipientName] = useState('');
  const [transferAmount, setTransferAmount] = useState('');
  const [fee, setFee] = useState(0);
  const [transferMsg, setTransferMsg] = useState({ show: false, message: '', type: 'success' });
  const [showPinModal, setShowPinModal] = useState(false);
  const [pinInput, setPinInput] = useState('');
  const [pinModalMsg, setPinModalMsg] = useState({ show: false, message: '' });
  const [hasPin, setHasPin] = useState(true);
  const [showSetPinModal, setShowSetPinModal] = useState(false);
  const [newPinInput, setNewPinInput] = useState('');
  const [newPinMsg, setNewPinMsg] = useState({ show: false, message: '' });

  // Transfer face-capture state
  const [transferStep, setTransferStep] = useState('form');   // form | face | processing
  const [transferFaceBase64, setTransferFaceBase64] = useState(null);
  const [transferFaceCaptured, setTransferFaceCaptured] = useState(false);
  const [transferFaceStream, setTransferFaceStream] = useState(null);
  const [transferFaceMsg, setTransferFaceMsg] = useState('');
  const transferVideoRef = useRef(null);
  const transferCanvasRef = useRef(null);
  
  // Reset PIN state
  const [resetStep, setResetStep] = useState(1);
  const [resetPhone, setResetPhone] = useState('');
  const [resetNationalId, setResetNationalId] = useState('');
  const [resetVerifiedName, setResetVerifiedName] = useState('');
  const [resetNewPin, setResetNewPin] = useState('');
  const [resetConfirmPin, setResetConfirmPin] = useState('');
  const [resetFaceBase64, setResetFaceBase64] = useState(null);
  const [resetFaceCaptured, setResetFaceCaptured] = useState(false);
  const [resetFaceValid, setResetFaceValid] = useState(false);
  const [resetStream, setResetStream] = useState(null);
  
  // Update Face state
  const [updateStep, setUpdateStep] = useState(1);
  const [updateFacePhone, setUpdateFacePhone] = useState('');
  const [updateFaceNatId, setUpdateFaceNatId] = useState('');
  const [updateVerifiedName, setUpdateVerifiedName] = useState('');
  const [updateFaceBase64, setUpdateFaceBase64] = useState(null);
  const [updateFaceCaptured, setUpdateFaceCaptured] = useState(false);
  const [updateFaceValid, setUpdateFaceValid] = useState(false);
  const [updateStream, setUpdateStream] = useState(null);
  
  // Profile state
  const [profile, setProfile] = useState(null);
  
  // Refs
  const resetFaceVideoRef = useRef(null);
  const resetFaceCanvasRef = useRef(null);
  const updateFaceVideoRef = useRef(null);
  const updateFaceCanvasRef = useRef(null);
  
  useEffect(() => {
    const token = TOKEN();
    if (!token) {
      navigate('/login');
      return;
    }
    init();
  }, []);
  
  useEffect(() => {
    if (activePage === 'balance') loadBalance();
    if (activePage === 'history') loadHistory();
    if (activePage === 'profile') loadProfile();
  }, [activePage]);
  
  useEffect(() => {
    return () => {
      if (resetStream) resetStream.getTracks().forEach(t => t.stop());
      if (updateStream) updateStream.getTracks().forEach(t => t.stop());
      if (transferFaceStream) transferFaceStream.getTracks().forEach(t => t.stop());
    };
  }, [resetStream, updateStream, transferFaceStream]);
  
  const init = async () => {
    try {
      const r = await fetch(`${API}/api/validate-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_token: TOKEN() })
      });
      const d = await r.json();
      if (!d.success) {
        navigate('/login');
        return;
      }
      setCurrentUser(d.user);
      setHasPin(d.has_pin !== false);
      if (d.has_pin === false) setShowSetPinModal(true);
      loadBalance();
    } catch {
      navigate('/login');
    }
  };
  
  const loadBalance = async () => {
    try {
      const r = await fetch(`${API}/api/user/balance`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_token: TOKEN() })
      });
      const d = await r.json();
      if (d.success) {
        setBalance(d.balance);
        setTransactions(d.transactions || []);
      }
    } catch (e) {
      console.error('Balance error:', e);
    }
  };
  
  const loadHistory = async () => {
    try {
      const r = await fetch(`${API}/api/user/history`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_token: TOKEN() })
      });
      const d = await r.json();
      setHistory(d.history || []);  // always set, even on failure
    } catch (e) {
      console.error('History error:', e);
      setHistory([]);  // stop the spinner on error too
    }
  };
  
  const loadProfile = async () => {
    try {
      const r = await fetch(`${API}/api/user/profile`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_token: TOKEN() })
      });
      const d = await r.json();
      if (d.success) {
        setProfile(d.user);
      }
    } catch (e) {
      console.error('Profile error:', e);
    }
  };
  
  const lookupRecipient = async () => {
    if (recipientPhone.length !== 9) return;
    try {
      const r = await fetch(`${API}/api/user/lookup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          session_token: TOKEN(),
          phone: '+250' + recipientPhone 
        })
      });
      const d = await r.json();
      if (d.success && d.registered) {
        if (d.blocked) {
          setRecipientName(` ${d.blocked_reason}`);
        } else {
          setRecipientName(` ${d.name}`);
        }
      } else if (d.success && !d.registered) {
        setRecipientName(' Phone not registered in system');
      } else {
        setRecipientName('');
      }
    } catch (e) {
      console.error('Lookup error:', e);
    }
  };
  
  const onAmountInput = (value) => {
    setTransferAmount(value);
    const amount = parseFloat(value) || 0;
    let calculatedFee = 0;
    if (amount >= 1 && amount <= 1000)          calculatedFee = 20;
    else if (amount <= 10000)                   calculatedFee = 100;
    else if (amount <= 150000)                  calculatedFee = 250;
    else if (amount <= 2000000)                 calculatedFee = 1500;
    setFee(calculatedFee);
  };
  
  // ── Transfer face capture helpers ────────────────────────────────────

  const startTransferCamera = async () => {
    try {
      const s = await navigator.mediaDevices.getUserMedia({
        video: { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: 'user' }
      });
      setTransferFaceStream(s);
      setTransferFaceCaptured(false);
      setTransferFaceBase64(null);
      setTransferFaceMsg('');
      if (transferVideoRef.current) {
        transferVideoRef.current.srcObject = s;
        transferVideoRef.current.style.transform = 'scaleX(-1)';
      }
    } catch (e) {
      setTransferFaceMsg('Camera access denied. Please allow camera access.');
    }
  };

  const captureTransferFace = () => {
    const video  = transferVideoRef.current;
    const canvas = transferCanvasRef.current;
    if (!video || !canvas) return;

    canvas.width  = video.videoWidth  || 1280;
    canvas.height = video.videoHeight || 720;
    const ctx = canvas.getContext('2d');
    ctx.translate(canvas.width, 0);
    ctx.scale(-1, 1);
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    ctx.setTransform(1, 0, 0, 1, 0, 0);

    // Brightness check
    const data = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
    let total = 0;
    for (let i = 0; i < data.length; i += 4)
      total += 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];
    const avg = total / (data.length / 4);
    if (avg < 35) { setTransferFaceMsg('⚠️ Too dark — move to a brighter area.'); return; }
    if (avg > 240) { setTransferFaceMsg('⚠️ Too bright — reduce glare.'); return; }

    setTransferFaceMsg('');
    const scaled = document.createElement('canvas');
    scaled.width  = 480;
    scaled.height = Math.round(canvas.height * 480 / canvas.width);
    scaled.getContext('2d').drawImage(canvas, 0, 0, scaled.width, scaled.height);
    const base64 = scaled.toDataURL('image/jpeg', 0.85).split(',')[1];

    setTransferFaceBase64(base64);
    setTransferFaceCaptured(true);
    if (transferFaceStream) { transferFaceStream.getTracks().forEach(t => t.stop()); setTransferFaceStream(null); }
  };

  const retakeTransferFace = () => {
    setTransferFaceBase64(null);
    setTransferFaceCaptured(false);
    startTransferCamera();
  };

  const doTransfer = async () => {
    if (!recipientPhone || !transferAmount) {
      showAlert(setTransferMsg, 'Please fill in all fields', 'error');
      return;
    }
    setShowPinModal(true);
  };
  
  const confirmTransfer = async () => {
    if (!pinInput || pinInput.length < 4) {
      setPinModalMsg({ show: true, message: 'Please enter a valid PIN' });
      return;
    }
    
    try {
      // First verify PIN
      const pinR = await fetch(`http://localhost:5000/api/verify-pin`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + TOKEN()
        },
        body: JSON.stringify({ pin: pinInput })
      });
      const pinD = await pinR.json();
      if (!pinD.success) {
        setPinModalMsg({ show: true, message: pinD.error || 'Incorrect PIN' });
        return;
      }

      // PIN ok — move to face scan step
      setShowPinModal(false);
      setTransferStep('face');
      // Start camera automatically
      setTimeout(() => startTransferCamera(), 300);

    } catch (e) {
      setPinModalMsg({ show: true, message: 'Network error. Please try again.' });
    }
  };

  const submitTransferWithFace = async () => {
    if (!transferFaceBase64) {
      setTransferFaceMsg('Please capture your face first.');
      return;
    }
    setTransferStep('processing');
    try {
      const r = await fetch(`http://localhost:5000/api/transfer`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + TOKEN()
        },
        body: JSON.stringify({
          session_token: TOKEN(),
          recipient_phone: '+250' + recipientPhone,
          amount: parseFloat(transferAmount),
          face_base64: transferFaceBase64
        })
      });
      const d = await r.json();

      setTransferStep('form');

      if (d.action === 'ABROAD_PENDING' || d.abroad_pending) {
        showAlert(setTransferMsg, d.message || 'Transfer pending owner approval.', 'info');
      } else if (d.success) {
        showAlert(setTransferMsg, 'Transfer successful! ✅', 'success');
        setRecipientPhone('');
        setRecipientName('');
        setTransferAmount('');
        setFee(0);
        loadBalance();
      } else {
        showAlert(setTransferMsg, d.message || d.error || 'Transfer failed', 'error');
      }
      // Reset face state
      setTransferFaceBase64(null);
      setTransferFaceCaptured(false);
      setPinInput('');
    } catch (e) {
      setTransferStep('form');
      showAlert(setTransferMsg, 'Network error. Please try again.', 'error');
    }
  };
  
  // Reset PIN functions
  const rpVerifyIdentity = async () => {
    try {
      const r = await fetch(`${API}/api/user/verify-identity`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          phone_number: resetPhone,
          national_id: resetNationalId
        })
      });
      const d = await r.json();
      if (d.success) {
        setResetVerifiedName(d.name);
        setResetStep(2);
      } else {
        showAlert(setTransferMsg, d.error || 'Identity verification failed', 'error');
      }
} catch (e) {
  showAlert(setTransferMsg, e.message || 'Network error. Please try again.', 'error');
}
  };
  
  const resetStartCamera = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: 'user' }
      });
      setResetStream(stream);
      if (resetFaceVideoRef.current) {
        resetFaceVideoRef.current.srcObject = stream;
        resetFaceVideoRef.current.style.display = 'block';
        resetFaceVideoRef.current.style.transform = 'scaleX(-1)';
      }
    } catch (e) {
      showAlert(setTransferMsg, 'Camera access denied', 'error');
    }
  };
  
  const resetCaptureFace = () => {
    const video = resetFaceVideoRef.current;
    const canvas = resetFaceCanvasRef.current;
    if (!video || !canvas) return;
    
    canvas.width = video.videoWidth || 1280;
    canvas.height = video.videoHeight || 720;
    const ctx = canvas.getContext('2d');
    ctx.translate(canvas.width, 0);
    ctx.scale(-1, 1);
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    ctx.setTransform(1, 0, 0, 1, 0, 0);

    // ── Quality check: reject dark/black or overexposed frames ──────────
    const sample = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const pixels = sample.data;
    let totalBrightness = 0;
    for (let i = 0; i < pixels.length; i += 4) {
      totalBrightness += (pixels[i] * 0.299 + pixels[i+1] * 0.587 + pixels[i+2] * 0.114);
    }
    const avgBrightness = totalBrightness / (pixels.length / 4);
    if (avgBrightness < 40) {
      showAlert(setTransferMsg,
        '⚠️ Image is too dark. Move to a brighter area and try again.', 'error');
      return;
    }
    if (avgBrightness > 230) {
      showAlert(setTransferMsg,
        ' Image is too bright / overexposed. Avoid direct light behind you.', 'error');
      return;
    }

    const base64 = canvas.toDataURL('image/jpeg', 0.95).split(',')[1];

    // Check if half the image is black (camera not covering full frame)
    const leftSample = ctx.getImageData(0, 0, canvas.width / 2, canvas.height);
    const rightSample = ctx.getImageData(canvas.width / 2, 0, canvas.width / 2, canvas.height);
    const avgLeft = Array.from(leftSample.data).filter((_, i) => i % 4 !== 3).reduce((a, b) => a + b, 0) / (leftSample.data.length * 3 / 4);
    const avgRight = Array.from(rightSample.data).filter((_, i) => i % 4 !== 3).reduce((a, b) => a + b, 0) / (rightSample.data.length * 3 / 4);
    if (Math.abs(avgLeft - avgRight) > 80) {
      showAlert(setTransferMsg, ' Camera not properly positioned. Center your face and try again.', 'error');
      return;
    }

    setResetFaceBase64(base64);
    setResetFaceCaptured(true);
    setResetFaceValid(true);
    if (resetFaceVideoRef.current) resetFaceVideoRef.current.style.display = 'none';
    if (resetStream) {
      resetStream.getTracks().forEach(t => t.stop());
      setResetStream(null);
    }
  };
  
  const resetRetake = () => {
    setResetFaceBase64(null);
    setResetFaceCaptured(false);
    setResetFaceValid(false);
    resetStartCamera();
  };
  
  const doResetPin = async () => {
    if (!resetFaceValid) return;
    try {
      const r = await fetch(`${API}/api/user/reset-pin`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + TOKEN()
        },
        body: JSON.stringify({
          national_id: resetNationalId,
          new_pin: resetNewPin,
          face_base64: resetFaceBase64
        })
      });
      const d = await r.json();
      if (d.success) {
        showAlert(setTransferMsg, 'PIN reset successful!', 'success');
        setResetStep(1);
        setResetPhone('');
        setResetNationalId('');
        setResetNewPin('');
        setResetConfirmPin('');
        setResetFaceBase64(null);
        setResetFaceCaptured(false);
        setResetFaceValid(false);
      } else {
        showAlert(setTransferMsg, d.error || 'PIN reset failed', 'error');
      }
    } catch (e) {
      showAlert(setTransferMsg, 'Network error. Please try again.', 'error');
    }
  };
  
  // Update Face functions
  const ufVerifyIdentity = async () => {
    try {
      const r = await fetch(`${API}/api/user/verify-identity`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          phone_number: updateFacePhone,
          national_id: updateFaceNatId
        })
      });
      const d = await r.json();
      if (d.success) {
        setUpdateVerifiedName(d.name);
        setUpdateStep(2);
      } else {
        showAlert(setTransferMsg, d.error || 'Identity verification failed', 'error');
      }
    } catch (e) {
      showAlert(setTransferMsg, 'Network error. Please try again.', 'error');
    }
  };
  
  const ufStartCamera = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: 'user' }
      });
      setUpdateStream(stream);
      if (updateFaceVideoRef.current) {
        updateFaceVideoRef.current.srcObject = stream;
        updateFaceVideoRef.current.style.display = 'block';
        updateFaceVideoRef.current.style.transform = 'scaleX(-1)';
      }
    } catch (e) {
      showAlert(setTransferMsg, 'Camera access denied', 'error');
    }
  };
  
  const ufCapture = () => {
    const video = updateFaceVideoRef.current;
    const canvas = updateFaceCanvasRef.current;
    if (!video || !canvas) return;

    canvas.width = video.videoWidth || 1280;
    canvas.height = video.videoHeight || 720;
    const ctx = canvas.getContext('2d');
    ctx.translate(canvas.width, 0);
    ctx.scale(-1, 1);
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    ctx.setTransform(1, 0, 0, 1, 0, 0);

    // ── Quality check: reject dark/black frames ──────────────────────
    const sample = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const pixels = sample.data;
    let totalBrightness = 0;
    for (let i = 0; i < pixels.length; i += 4) {
      totalBrightness += (pixels[i] * 0.299 + pixels[i+1] * 0.587 + pixels[i+2] * 0.114);
    }
    const avgBrightness = totalBrightness / (pixels.length / 4);
    if (avgBrightness < 40) {
      showAlert(setTransferMsg,
        '⚠️ Image is too dark. Move to a brighter area and try again.', 'error');
      return;
    }
    if (avgBrightness > 230) {
      showAlert(setTransferMsg,
        ' Image is too bright / overexposed. Avoid direct light behind you.', 'error');
      return;
    }

    const base64 = canvas.toDataURL('image/jpeg', 0.95).split(',')[1];

    // Check if half the image is black (camera not covering full frame)
    const leftSample = ctx.getImageData(0, 0, canvas.width / 2, canvas.height);
    const rightSample = ctx.getImageData(canvas.width / 2, 0, canvas.width / 2, canvas.height);
    const avgLeft = Array.from(leftSample.data).filter((_, i) => i % 4 !== 3).reduce((a, b) => a + b, 0) / (leftSample.data.length * 3 / 4);
    const avgRight = Array.from(rightSample.data).filter((_, i) => i % 4 !== 3).reduce((a, b) => a + b, 0) / (rightSample.data.length * 3 / 4);
    if (Math.abs(avgLeft - avgRight) > 80) {
      showAlert(setTransferMsg, ' Camera not properly positioned. Center your face and try again.', 'error');
      return;
    }

    setUpdateFaceBase64(base64);
    setUpdateFaceCaptured(true);
    setUpdateFaceValid(true);
    if (updateFaceVideoRef.current) updateFaceVideoRef.current.style.display = 'none';
    if (updateStream) {
      updateStream.getTracks().forEach(t => t.stop());
      setUpdateStream(null);
    }
  };
  
  const ufRetake = () => {
    setUpdateFaceBase64(null);
    setUpdateFaceCaptured(false);
    setUpdateFaceValid(false);
    ufStartCamera();
  };
  
  const doUpdateFace = async () => {
    if (!updateFaceValid) return;
    try {
      const r = await fetch(`${API}/api/user/update-face`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + TOKEN()
        },
        body: JSON.stringify({
          phone_number: updateFacePhone,
          national_id: updateFaceNatId,
          face_base64: updateFaceBase64,
          session_token: TOKEN()
        })
      });
      const d = await r.json();
      if (d.success) {
        showAlert(setTransferMsg, 'Face updated successfully!', 'success');
        setUpdateStep(1);
        setUpdateFacePhone('');
        setUpdateFaceNatId('');
        setUpdateFaceBase64(null);
        setUpdateFaceCaptured(false);
        setUpdateFaceValid(false);
      } else {
        showAlert(setTransferMsg, d.error || 'Face update failed', 'error');
      }
    } catch (e) {
      showAlert(setTransferMsg, 'Network error. Please try again.', 'error');
    }
  };
  
  const doLogout = () => {
    fetch(`${API}/api/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_token: TOKEN() })
    }).catch(() => {});
    localStorage.clear();
    navigate('/login');
  };

  const doSetPin = async () => {
    if (!newPinInput || newPinInput.length < 4) {
      setNewPinMsg({ show: true, message: 'PIN must be at least 4 digits.' });
      return;
    }
    try {
      const r = await fetch(`http://localhost:5000/api/set-pin`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + TOKEN()
        },
        body: JSON.stringify({ pin: newPinInput })
      });
      const d = await r.json();
      if (d.success) {
        setHasPin(true);
        setShowSetPinModal(false);
        setNewPinInput('');
      } else {
        setNewPinMsg({ show: true, message: d.error || 'Failed to set PIN.' });
      }
    } catch (e) {
      setNewPinMsg({ show: true, message: 'Network error.' });
    }
  };
  
  const initials = currentUser?.name?.split(' ').map(n => n[0]).join('').toUpperCase() || 'UE';
  
  return (
    <div className="flex min-h-screen bg-white">
      {/* Sidebar */}
      <aside className="w-[230px] flex-shrink-0 bg-white border-2 border-slate-300 rounded-2xl m-4 h-[calc(100vh-32px)] flex flex-col relative z-10 overflow-hidden shadow-lg">
        <div className="p-4 border-b border-slate-300 text-center">
          <div className="w-14 h-14 rounded-full bg-gradient-to-br from-emerald-500 to-sky-500 text-white flex items-center justify-center text-xl font-bold mx-auto mb-2">
            {initials}
          </div>
          <div className="font-bold text-sm bg-gradient-to-r from-emerald-500 to-sky-500 bg-clip-text text-transparent leading-tight">
            MoMo Shield
          </div>
          <div className="text-[10px] text-slate-400 leading-tight mb-2">User Dashboard</div>
          {currentUser && (
            <>
              <div className="text-xs font-semibold text-slate-800 leading-tight">{currentUser.name}</div>
              <div className="text-[10px] text-slate-500 font-mono leading-tight">{currentUser.phone}</div>
            </>
          )}
        </div>
        
        <nav className="p-3.5 flex-1 min-h-0 overflow-y-auto text-left">
          <div className="text-[10px] uppercase tracking-wider text-slate-500 px-3.5 py-3.5 pb-1.5">My Account</div>
          <NavItem page="balance" icon={Wallet} label="Balance" activePage={activePage} setActivePage={setActivePage} />
          <NavItem page="transfer" icon={Send} label="Send Money" activePage={activePage} setActivePage={setActivePage} />
          <NavItem page="history" icon={History} label="History" activePage={activePage} setActivePage={setActivePage} />
          <NavItem page="reset-pin" icon={Lock} label="Reset PIN" activePage={activePage} setActivePage={setActivePage} />
          <NavItem page="update-face" icon={User} label="Update Face" activePage={activePage} setActivePage={setActivePage} />
          <NavItem page="profile" icon={User} label="Profile" activePage={activePage} setActivePage={setActivePage} />
        </nav>
        
        <Button variant="ghost" onClick={doLogout} className="mx-4 mb-4 w-[calc(100%-32px)] justify-center">
          <LogOut className="w-4 h-4" />
          Logout
        </Button>
      </aside>
      
      {/* Main Content */}
      <main className="flex-1 flex flex-col relative z-5 h-screen overflow-y-auto p-6">
        {/* Balance Page */}
        {activePage === 'balance' && (
          <div>
            <div className="text-center mb-6">
              <h1 className="text-2xl font-bold bg-gradient-to-r from-emerald-500 to-sky-500 bg-clip-text text-transparent">
                My Balance
              </h1>
              <p className="text-sm text-slate-500 mt-1">Account overview and quick actions</p>
            </div>
            
            <div className="grid grid-cols-2 gap-5">
              <Card>
                <div className="p-6 border-b border-slate-300 flex flex-col items-center text-center">
                  <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-emerald-500 to-sky-500 flex items-center justify-center mb-2.5">
                    <Wallet className="w-5 h-5 text-white" />
                  </div>
                  <h2 className="text-base font-semibold">Account Balance</h2>
                </div>
                <div className="p-9 text-center">
                  <div className="text-[2.4rem] font-bold font-mono text-emerald-500">{fmtRWF(balance)}</div>
                  <div className="text-xs text-slate-500 mt-1.5">Rwanda Francs</div>
                  <div className="mt-6">
                    <Button onClick={() => setActivePage('transfer')} className="px-5 text-xs">Send Money</Button>
                  </div>
                </div>
              </Card>
              
              <Card>
                <div className="p-6 border-b border-slate-300 flex flex-col items-center text-center">
                  <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-purple-500 to-sky-500 flex items-center justify-center mb-2.5">
                    <History className="w-5 h-5 text-white" />
                  </div>
                  <h2 className="text-base font-semibold">Recent Activity</h2>
                </div>
                <div className="p-0">
                  {transactions.length === 0 ? (
                    <div className="text-center text-slate-500 p-10 text-sm">No recent transactions</div>
                  ) : (
                    transactions.slice(0, 5).map((tx) => (
                      <div key={tx.id} className="flex justify-between items-center p-4 border-b border-slate-300 text-xs">
                        <div>
                          <div className="font-semibold">{tx.direction === 'sent' ? '→ ' + (tx.recipient_phone || tx.recipient || '—') : '← ' + (tx.sender_phone || tx.sender || '—')}</div>
                          <div className="text-slate-500">{fmtDate(tx.created_at)}</div>
                        </div>
                        <div className="text-right">
                          <div className={`font-semibold ${tx.direction === 'sent' ? 'text-red-500' : 'text-emerald-500'}`}>
                            {tx.direction === 'sent' ? '-' : '+'}{fmtRWF(Math.abs(tx.amount))}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </Card>
            </div>
          </div>
        )}
        
        {/* Transfer Page */}
        {activePage === 'transfer' && (
          <div>
            <div className="text-center mb-6">
              <h1 className="text-2xl font-bold bg-gradient-to-r from-emerald-500 to-sky-500 bg-clip-text text-transparent">
                Send Money
              </h1>
              <p className="text-sm text-slate-500 mt-1">Secure transfer with real-time fraud protection</p>
            </div>
            
            <div className="max-w-[480px] mx-auto">

              {/* ── Step 1: Transfer Form ── */}
              {transferStep === 'form' && (
              <Card>
                <div className="p-6 border-b border-slate-300 flex flex-col items-center text-center">
                  <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-emerald-500 to-sky-500 flex items-center justify-center mb-2.5">
                    <Send className="w-5 h-5 text-white" />
                  </div>
                  <h2 className="text-base font-semibold">New Transfer</h2>
                </div>
                <div className="p-6">
                  <AlertMsg msg={transferMsg} />
                  
                  <div className="mb-5">
                    <label className="block text-xs font-semibold text-slate-900 mb-1.5">Recipient Phone</label>
                    <div className="flex items-center border border-slate-300 rounded-lg bg-slate-50 focus-within:border-emerald-500 focus-within:ring-3 focus-within:ring-emerald-500/10">
                      <span className="px-3.5 py-2.5 text-slate-500 font-mono text-sm border-r border-slate-300">+250</span>
                      <input
                        type="text"
                        value={recipientPhone}
                        onChange={(e) => {
                        const val = e.target.value.replace(/\D/g, '').slice(0, 9);
                        setRecipientPhone(val);
                        if (val.length === 9) lookupRecipient();
                        }}
                        onBlur={lookupRecipient}
                        placeholder="78XXXXXXX"
                        maxLength={10}
                        className="flex-1 px-3.5 py-2.5 border-none bg-none text-sm focus:outline-none"
                      />
                    </div>
                    {recipientName && (
                      <div className="mt-1.5 px-3 py-2 rounded-lg text-xs bg-emerald-500/8 border border-emerald-500/20 text-emerald-500 font-semibold">
                        {recipientName}
                      </div>
                    )}
                  </div>
                  
                  <div className="mb-5">
                    <label className="block text-xs font-semibold text-slate-900 mb-1.5">Amount (RWF)</label>
                    <input
                      type="text"
                      inputMode="numeric"
                      value={transferAmount}
                      onChange={(e) => {
                      const val = e.target.value.replace(/[^0-9.]/g, '');
                      onAmountInput(val);
                      }}
                      placeholder="5000"
                      className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg bg-slate-50 text-sm focus:border-emerald-500 focus:ring-3 focus:ring-emerald-500/10 outline-none"
                    />
                  </div>
                  
                  {transferAmount && (
                    <div className="mb-5 bg-slate-50 border border-slate-300 rounded-lg p-4 text-xs">
                      <div className="flex justify-between py-1">
                        <span>Amount</span>
                        <span>{fmtRWF(parseFloat(transferAmount) || 0)}</span>
                      </div>
                      <div className="flex justify-between py-1">
                        <span>Fee</span>
                        <span>{fmtRWF(fee)}</span>
                      </div>
                      <div className="flex justify-between py-1 border-t border-slate-300 mt-1 pt-1 font-bold">
                        <span>Total deducted</span>
                        <span>{fmtRWF((parseFloat(transferAmount) || 0) + fee)}</span>
                      </div>
                    </div>
                  )}

                  {/* Security note */}
                  <div className="mb-4 flex items-center gap-2 bg-emerald-50 border border-emerald-200 rounded-lg p-3 text-xs text-emerald-700">
                    <Shield className="w-4 h-4 flex-shrink-0" />
                    Face verification required for every transfer
                  </div>
                  
                  <Button onClick={doTransfer} className="w-full justify-center">
                    <Send className="w-4 h-4" />
                    Send Money
                  </Button>
                </div>
              </Card>
              )}

              {/* ── Step 2: Face Scan ── */}
              {transferStep === 'face' && (
              <Card>
                <div className="p-6 border-b border-slate-300 flex flex-col items-center text-center">
                  <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-emerald-500 to-sky-500 flex items-center justify-center mb-2.5">
                    <Camera className="w-5 h-5 text-white" />
                  </div>
                  <h2 className="text-base font-semibold">Face Verification</h2>
                  <p className="text-xs text-slate-500 mt-1">Required for every transaction — confirm it's you</p>
                </div>
                <div className="p-6">
                  {/* Transfer summary */}
                  <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 mb-4 text-xs">
                    <div className="flex justify-between mb-1">
                      <span className="text-slate-500">To</span>
                      <span className="font-mono font-semibold">+250{recipientPhone}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Total</span>
                      <span className="font-bold text-emerald-600">{fmtRWF((parseFloat(transferAmount)||0) + fee)}</span>
                    </div>
                  </div>

                  {transferFaceMsg && (
                    <div className="bg-amber-50 border border-amber-200 rounded-lg p-2.5 text-xs text-amber-700 mb-3 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                      {transferFaceMsg}
                    </div>
                  )}

                  {/* Camera area */}
                  <div className="rounded-xl overflow-hidden border-2 border-slate-300 mb-4 bg-black relative">
                    <video
                      ref={transferVideoRef}
                      autoPlay muted playsInline
                      className={`w-full ${transferFaceCaptured ? 'hidden' : 'block'}`}
                    />
                    {transferFaceCaptured && transferFaceBase64 && (
                      <img src={`data:image/jpeg;base64,${transferFaceBase64}`}
                           alt="Captured" className="w-full" />
                    )}
                    {!transferFaceCaptured && (
                      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                        <div className="w-36 h-44 border-2 border-emerald-400 border-dashed rounded-full opacity-50" />
                      </div>
                    )}
                    {!transferFaceStream && !transferFaceCaptured && (
                      <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-400 gap-2">
                        <Camera className="w-8 h-8 opacity-40" />
                        <span className="text-xs">Camera preview</span>
                      </div>
                    )}
                  </div>
                  <canvas ref={transferCanvasRef} className="hidden" />

                  {!transferFaceStream && !transferFaceCaptured && (
                    <button onClick={startTransferCamera}
                      className="w-full py-3 bg-gradient-to-br from-emerald-500 to-sky-500 text-white rounded-[14px] font-bold text-sm flex items-center justify-center gap-2 hover:shadow-lg transition-all mb-2">
                      <Camera className="w-4 h-4" /> Open Camera
                    </button>
                  )}

                  {transferFaceStream && !transferFaceCaptured && (
                    <button onClick={captureTransferFace}
                      className="w-full py-3 bg-gradient-to-br from-emerald-500 to-sky-500 text-white rounded-[14px] font-bold text-sm flex items-center justify-center gap-2 hover:shadow-lg transition-all mb-2">
                      <Camera className="w-4 h-4" /> Capture
                    </button>
                  )}

                  {transferFaceCaptured && (
                    <div className="space-y-2">
                      <button onClick={submitTransferWithFace}
                        className="w-full py-3 bg-gradient-to-br from-emerald-500 to-sky-500 text-white rounded-[14px] font-bold text-sm flex items-center justify-center gap-2 hover:shadow-lg transition-all">
                        <Check className="w-4 h-4" /> Confirm & Send
                      </button>
                      <button onClick={retakeTransferFace}
                        className="w-full py-2.5 bg-transparent text-emerald-600 border border-emerald-500 rounded-[14px] font-semibold text-sm flex items-center justify-center gap-2 hover:bg-emerald-50 transition-all">
                        <RefreshCw className="w-4 h-4" /> Retake
                      </button>
                    </div>
                  )}

                  <button onClick={() => { setTransferStep('form'); if(transferFaceStream) transferFaceStream.getTracks().forEach(t=>t.stop()); setTransferFaceStream(null); setTransferFaceCaptured(false); setTransferFaceBase64(null); }}
                    className="w-full mt-2 py-2 bg-transparent text-slate-500 text-xs hover:text-slate-700 transition-all">
                    ← Cancel
                  </button>
                </div>
              </Card>
              )}

              {/* ── Step 3: Processing ── */}
              {transferStep === 'processing' && (
              <Card>
                <div className="p-16 text-center">
                  <div className="w-12 h-12 border-3 border-emerald-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
                  <p className="text-sm font-semibold text-slate-700">Verifying face &amp; processing transfer…</p>
                  <p className="text-xs text-slate-400 mt-1">Please wait</p>
                </div>
              </Card>
              )}

            </div>
          </div>
        )}
        
        {/* History Page */}
        {activePage === 'history' && (
          <div>
            <div className="text-center mb-6">
              <h1 className="text-2xl font-bold bg-gradient-to-r from-emerald-500 to-sky-500 bg-clip-text text-transparent">
                Transaction History
              </h1>
              <p className="text-sm text-slate-500 mt-1">Your recent money transfers</p>
            </div>
            <Card>
              <div className="p-6 border-b border-slate-300 flex flex-col items-center text-center">
                <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-purple-500 to-sky-500 flex items-center justify-center mb-2.5">
                  <History className="w-5 h-5 text-white" />
                </div>
                <h2 className="text-base font-semibold">Recent Transfers</h2>
              </div>
              <div className="p-0">
                {history.length === 0 ? (
                  <div className="text-center text-slate-500 p-10 text-sm">No transactions yet</div>
                ) : (
                  history.map((tx) => (
                    <div key={tx.id} className="flex justify-between items-center p-4 border-b border-slate-300 text-xs">
                      <div>
                        <div className="font-semibold">{tx.direction === 'sent' ? '→ ' + (tx.recipient || tx.recipient_phone || '—') : '← ' + (tx.sender_phone || '—')}</div>
                        <div className="text-slate-500">{fmtDate(tx.created_at)}</div>
                        <div className={`text-[11px] ${tx.status === 'completed' ? 'text-emerald-500' : tx.status === 'blocked' ? 'text-red-500' : 'text-amber-500'}`}>
                          {(tx.status || 'completed').toUpperCase()}
                        </div>
                      </div>
                      <div className="text-right">
                        <div className={`font-semibold ${tx.direction === 'sent' ? 'text-red-500' : 'text-emerald-500'}`}>
                          {tx.direction === 'sent' ? '-' : '+'}{fmtRWF(Math.abs(tx.amount))}
                        </div>
                        <div className="text-slate-500">Fee: {fmtRWF(tx.fee || 0)}</div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </Card>
          </div>
        )}
        
        {/* Profile Page */}
        {activePage === 'profile' && (
          <div>
            <div className="text-center mb-6">
              <h1 className="text-2xl font-bold bg-gradient-to-r from-emerald-500 to-sky-500 bg-clip-text text-transparent">
                My Profile
              </h1>
              <p className="text-sm text-slate-500 mt-1">Account information and settings</p>
            </div>
            
            <div className="max-w-[600px] mx-auto">
              <Card>
                <div className="p-6 border-b border-slate-300 flex flex-col items-center text-center">
                  <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-emerald-500 to-sky-500 flex items-center justify-center mb-2.5">
                    <User className="w-5 h-5 text-white" />
                  </div>
                  <h2 className="text-base font-semibold">Account Details</h2>
                </div>
                <div className="p-6">
                  <div className="flex justify-between py-3 border-b border-slate-200 text-xs">
                    <span className="text-slate-500">Full Name</span>
                    <span className="font-semibold font-mono">{profile?.name || '—'}</span>
                  </div>
                  <div className="flex justify-between py-3 border-b border-slate-200 text-xs">
                    <span className="text-slate-500">Phone Number</span>
                    <span className="font-semibold font-mono">{profile?.phone || '—'}</span>
                  </div>
                  <div className="flex justify-between py-3 border-b border-slate-200 text-xs">
                    <span className="text-slate-500">Email</span>
                    <span className="font-semibold font-mono">{profile?.email || '—'}</span>
                  </div>
                  <div className="flex justify-between py-3 border-b border-slate-200 text-xs">
                    <span className="text-slate-500">National ID</span>
                    <span className="font-semibold font-mono">{profile?.national_id || '—'}</span>
                  </div>
                  <div className="flex justify-between py-3 text-xs">
                    <span className="text-slate-500">Account Status</span>
                    <span className="font-semibold font-mono">Active</span>
                  </div>
                </div>
              </Card>
            </div>
          </div>
        )}
        
        {/* Reset PIN Page */}
        {activePage === 'reset-pin' && (
          <div>
            <div className="text-center mb-6">
              <h1 className="text-2xl font-bold bg-gradient-to-r from-emerald-500 to-sky-500 bg-clip-text text-transparent">
                Reset PIN
              </h1>
              <p className="text-sm text-slate-500 mt-1">Verify your identity to reset your transaction PIN</p>
            </div>
            
            <div className="max-w-[480px] mx-auto">
              <Card>
                <div className="p-6 border-b border-slate-300 flex flex-col items-center text-center">
                  <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-amber-500 to-red-500 flex items-center justify-center mb-2.5">
                    <Lock className="w-5 h-5 text-white" />
                  </div>
                  <h2 className="text-base font-semibold">PIN Reset</h2>
                  <p className="text-xs text-slate-500 mt-0.5">3 steps: identity → new PIN → face scan</p>
                </div>
                <div className="p-6">
                  <AlertMsg msg={transferMsg} />
                  
                  {resetStep === 1 && (
                    <div>
                      <p className="text-xs text-slate-500 mb-3.5 text-center"><strong>Step 1 of 3</strong> — Verify your identity</p>
                      <div className="mb-5">
                        <label className="block text-xs font-semibold text-slate-900 mb-1.5">Phone Number</label>
                        <input
                          type="tel"
                          value={resetPhone}
                          onChange={(e) => setResetPhone(e.target.value)}
                          placeholder="e.g. 0780000000"
                          className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg bg-slate-50 text-sm focus:border-emerald-500 focus:ring-3 focus:ring-emerald-500/10 outline-none"
                        />
                      </div>
                      <div className="mb-5">
                        <label className="block text-xs font-semibold text-slate-900 mb-1.5">National ID (16 digits)</label>
                        <input
                          type="text"
                          value={resetNationalId}
                          onChange={(e) => setResetNationalId(e.target.value.replace(/\D/g, '').slice(0, 16))}
                          placeholder="Enter your 16-digit National ID"
                          maxLength={16}
                          className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg bg-slate-50 text-sm focus:border-emerald-500 focus:ring-3 focus:ring-emerald-500/10 outline-none"
                        />
                      </div>
                      <Button onClick={rpVerifyIdentity} className="w-full justify-center">
                        <Check className="w-4 h-4" />
                        Verify Identity
                      </Button>
                    </div>
                  )}
                  
                  {resetStep === 2 && (
                    <div>
                      <p className="text-xs text-slate-500 mb-3.5 text-center">
                        <strong>Step 2 of 3</strong> — Set your new PIN
                        {resetVerifiedName && <span className="block text-emerald-500 font-semibold mt-1">{resetVerifiedName}</span>}
                      </p>
                      <div className="mb-5">
                        <label className="block text-xs font-semibold text-slate-900 mb-1.5">New PIN (4–6 digits)</label>
                        <input
                          type="password"
                          value={resetNewPin}
                          onChange={(e) => setResetNewPin(e.target.value)}
                          placeholder="••••"
                          maxLength={6}
                          className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg bg-slate-50 text-sm focus:border-emerald-500 focus:ring-3 focus:ring-emerald-500/10 outline-none"
                        />
                      </div>
                      <div className="mb-5">
                        <label className="block text-xs font-semibold text-slate-900 mb-1.5">Confirm New PIN</label>
                        <input
                          type="password"
                          value={resetConfirmPin}
                          onChange={(e) => setResetConfirmPin(e.target.value)}
                          placeholder="••••"
                          maxLength={6}
                          className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg bg-slate-50 text-sm focus:border-emerald-500 focus:ring-3 focus:ring-emerald-500/10 outline-none"
                        />
                      </div>
                      <Button onClick={() => setResetStep(3)} disabled={!resetNewPin || resetNewPin !== resetConfirmPin} className="w-full justify-center">
                        Continue
                      </Button>
                    </div>
                  )}
                  
                  {resetStep === 3 && (
                    <div>
                      <p className="text-xs text-slate-500 mb-3.5 text-center"><strong>Step 3 of 3</strong> — Scan your face to confirm</p>
                      <div className="rounded-xl overflow-hidden bg-black mb-2.5 min-h-[140px] flex items-center justify-center relative">
                        <video ref={resetFaceVideoRef} autoPlay playsInline className="w-full max-h-[200px] hidden transform -scale-x-100" />
                        <canvas ref={resetFaceCanvasRef} className="hidden absolute invisible w-0 h-0" />
                        {resetFaceCaptured && resetFaceBase64 && (
                          <img src={`data:image/jpeg;base64,${resetFaceBase64}`} alt="Face capture" className="w-full max-h-[200px] object-cover" />
                        )}
                        {!resetFaceCaptured && !resetStream && (
                          <div className="text-slate-500 text-sm p-7.5 text-center">
                            <Camera className="w-10 h-10 mx-auto mb-2 opacity-40" />
                            <span>Click below to scan your face</span>
                          </div>
                        )}
                      </div>
                      <div className="flex gap-2.5 mb-2.5">
                        {!resetStream && !resetFaceCaptured && (
                          <Button onClick={resetStartCamera} className="flex-1 justify-center">
                            <Camera className="w-4 h-4" />
                            Open Camera
                          </Button>
                        )}
                        {resetStream && !resetFaceCaptured && (
                          <Button onClick={resetCaptureFace} className="flex-1 justify-center">
                            <Check className="w-4 h-4" />
                            Capture Face
                          </Button>
                        )}
                        {resetFaceCaptured && (
                          <Button variant="ghost" onClick={resetRetake} className="flex-1 justify-center">
                            <RefreshCw className="w-4 h-4" />
                            Retake
                          </Button>
                        )}
                      </div>
                      <Button onClick={doResetPin} disabled={!resetFaceValid} className="w-full justify-center">
                        <Lock className="w-4 h-4" />
                        Reset PIN
                      </Button>
                    </div>
                  )}
                </div>
              </Card>
            </div>
          </div>
        )}
        
        {/* Update Face Page */}
        {activePage === 'update-face' && (
          <div>
            <div className="text-center mb-6">
              <h1 className="text-2xl font-bold bg-gradient-to-r from-emerald-500 to-sky-500 bg-clip-text text-transparent">
                Update Face
              </h1>
              <p className="text-sm text-slate-500 mt-1">Verify your identity then register a new face scan</p>
            </div>
            
            <div className="max-w-[480px] mx-auto">
              <Card>
                <div className="p-6 border-b border-slate-300 flex flex-col items-center text-center">
                  <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-emerald-500 to-sky-500 flex items-center justify-center mb-2.5">
                    <User className="w-5 h-5 text-white" />
                  </div>
                  <h2 className="text-base font-semibold">Update Face</h2>
                  <p className="text-xs text-slate-500 mt-0.5">2 steps: identity → face scan</p>
                </div>
                <div className="p-6">
                  <AlertMsg msg={transferMsg} />
                  
                  {updateStep === 1 && (
                    <div>
                      <p className="text-xs text-slate-500 mb-3.5 text-center"><strong>Step 1 of 2</strong> — Verify your identity</p>
                      <div className="mb-5">
                        <label className="block text-xs font-semibold text-slate-900 mb-1.5">Phone Number</label>
                        <input
                          type="tel"
                          value={updateFacePhone}
                          onChange={(e) => setUpdateFacePhone(e.target.value)}
                          placeholder="e.g. 0780000000"
                          className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg bg-slate-50 text-sm focus:border-emerald-500 focus:ring-3 focus:ring-emerald-500/10 outline-none"
                        />
                      </div>
                      <div className="mb-5">
                        <label className="block text-xs font-semibold text-slate-900 mb-1.5">National ID (16 digits)</label>
                        <input
                          type="text"
                          value={updateFaceNatId}
                          onChange={(e) => setUpdateFaceNatId(e.target.value.replace(/\D/g, '').slice(0, 16))}
                          placeholder="Enter your 16-digit National ID"
                          maxLength={16}
                          className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg bg-slate-50 text-sm focus:border-emerald-500 focus:ring-3 focus:ring-emerald-500/10 outline-none"
                        />
                      </div>
                      <Button onClick={ufVerifyIdentity} className="w-full justify-center">
                        <Check className="w-4 h-4" />
                        Verify Identity
                      </Button>
                    </div>
                  )}
                  
                  {updateStep === 2 && (
                    <div>
                      <p className="text-xs text-slate-500 mb-3.5 text-center">
                        <strong>Step 2 of 2</strong> — Scan your face
                        {updateVerifiedName && <span className="block text-emerald-500 font-semibold mt-1">{updateVerifiedName}</span>}
                      </p>
                      <p className="text-xs text-slate-500 mb-2.5">Your new face must match the face already on this account. Eyes, nose, mouth and chin must be clearly visible.</p>
                      <div className="rounded-xl overflow-hidden bg-black mb-2.5 min-h-[140px] flex items-center justify-center relative">
                        <video ref={updateFaceVideoRef} autoPlay playsInline className="w-full max-h-[200px] hidden transform -scale-x-100" />
                        <canvas ref={updateFaceCanvasRef} className="hidden absolute invisible w-0 h-0" />
                        {updateFaceCaptured && updateFaceBase64 && (
                          <img src={`data:image/jpeg;base64,${updateFaceBase64}`} alt="Face capture" className="w-full max-h-[200px] object-cover" />
                        )}
                        {!updateFaceCaptured && !updateStream && (
                          <div className="text-slate-500 text-sm p-7.5 text-center">
                            <Camera className="w-10 h-10 mx-auto mb-2 opacity-40" />
                            <span>Click below to open camera</span>
                          </div>
                        )}
                      </div>
                      <div className="flex gap-2.5 mb-2.5">
                        {!updateStream && !updateFaceCaptured && (
                          <Button onClick={ufStartCamera} className="w-full justify-center">
                            <Camera className="w-4 h-4" />
                            Open Camera
                          </Button>
                        )}
                        {updateStream && !updateFaceCaptured && (
                          <Button onClick={ufCapture} className="w-full justify-center">
                            <Check className="w-4 h-4" />
                            Capture Face
                          </Button>
                        )}
                        {updateFaceCaptured && (
                          <Button variant="ghost" onClick={ufRetake} className="flex-1 justify-center">
                            <RefreshCw className="w-4 h-4" />
                            Retake
                          </Button>
                        )}
                      </div>
                      <Button onClick={doUpdateFace} disabled={!updateFaceValid} className="w-full justify-center">
                        <User className="w-4 h-4" />
                        Update Face
                      </Button>
                    </div>
                  )}
                </div>
              </Card>
            </div>
          </div>
        )}
      </main>

      {/* Set PIN Banner */}
      {!hasPin && (
        <div className="fixed top-4 left-1/2 -translate-x-1/2 z-40 bg-amber-500 text-white px-6 py-3 rounded-xl shadow-lg text-sm font-semibold flex items-center gap-3">
          <AlertTriangle className="w-4 h-4" />
          You haven't set a PIN yet — required to send money.
          <button onClick={() => setShowSetPinModal(true)} className="underline ml-1">Set PIN now</button>
        </div>
      )}

      {/* Set PIN Modal */}
      {showSetPinModal && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center">
          <div className="bg-white rounded-2xl p-8 w-[320px] shadow-2xl text-center">
            <div className="w-14 h-14 rounded-full bg-gradient-to-br from-amber-500 to-red-500 flex items-center justify-center mx-auto mb-4">
              <Lock className="w-7 h-7 text-white" />
            </div>
            <h3 className="text-base font-bold mb-1">Set Your PIN</h3>
            <p className="text-xs text-slate-500 mb-4">Create a 4–6 digit PIN to authorize transfers</p>
            {newPinMsg.show && (
              <div className="p-2 rounded-lg text-xs mb-3 bg-rose-500/10 text-rose-500 border border-rose-500/20">
                {newPinMsg.message}
              </div>
            )}
            <input
              type="password"
              value={newPinInput}
              onChange={(e) => setNewPinInput(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="Enter 4–6 digit PIN"
              maxLength={6}
              className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg bg-slate-50 text-sm focus:border-emerald-500 outline-none mb-4"
            />
            <div className="flex gap-2">
              <Button variant="ghost" onClick={() => setShowSetPinModal(false)} className="flex-1 justify-center">
                Later
              </Button>
              <Button onClick={doSetPin} className="flex-1 justify-center">
                <Lock className="w-4 h-4" />
                Set PIN
              </Button>
            </div>
          </div>
        </div>
      )}
      
      {/* PIN Modal */}
      {showPinModal && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center">
          <div className="bg-white rounded-2xl p-8 w-[320px] shadow-2xl text-center">
            <div className="w-14 h-14 rounded-full bg-gradient-to-br from-emerald-500 to-sky-500 flex items-center justify-center mx-auto mb-4">
              <Lock className="w-7 h-7 text-white" />
            </div>
            <h3 className="text-base font-bold mb-1">Enter PIN</h3>
            <p className="text-xs text-slate-500 mb-4">Your 4–6 digit transaction PIN</p>
            {pinModalMsg.show && (
              <div className="p-2 rounded-lg text-xs mb-3 bg-rose-500/10 text-rose-500 border border-rose-500/20">
                {pinModalMsg.message}
              </div>
            )}
            <input
              type="password"
              value={pinInput}
              onChange={(e) => setPinInput(e.target.value)}
              placeholder="••••"
              maxLength={6}
              className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg bg-slate-50 text-sm focus:border-emerald-500 focus:ring-3 focus:ring-emerald-500/10 outline-none mb-4"
            />
            <div className="flex gap-2">
              <Button variant="ghost" onClick={() => { setShowPinModal(false); setPinInput(''); setPinModalMsg({ show: false, message: '' }); }} className="flex-1 justify-center">
                Cancel
              </Button>
              <Button onClick={confirmTransfer} className="flex-1 justify-center">
                Confirm
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
