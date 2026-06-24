import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Shield, Camera, Check, RefreshCw, AlertTriangle, Plane } from 'lucide-react';

const API = 'http://localhost:5000';

export default function AbroadVerify() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token') || '';

  const [step, setStep] = useState('loading');   // loading | info | capture | result
  const [info, setInfo] = useState(null);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  // Camera
  const [stream, setStream] = useState(null);
  const [faceBase64, setFaceBase64] = useState(null);
  const [faceCaptured, setFaceCaptured] = useState(false);
  const [qualityMsg, setQualityMsg] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const videoRef = useRef(null);
  const canvasRef = useRef(null);

  // Load transfer info on mount
  useEffect(() => {
    if (!token) { setError('No verification token found in link.'); setStep('result'); return; }
    loadInfo();
  }, [token]);

  // Cleanup camera on unmount
  useEffect(() => {
    return () => { if (stream) stream.getTracks().forEach(t => t.stop()); };
  }, [stream]);

  const loadInfo = async () => {
    try {
      const r = await fetch(`${API}/api/abroad-verify/info?token=${encodeURIComponent(token)}`);
      const d = await r.json();
      if (d.success) {
        setInfo(d);
        setStep('info');
      } else {
        setError(d.message || d.error || 'Invalid or expired link.');
        setStep('result');
      }
    } catch (e) {
      setError('Server error. Please try again.');
      setStep('result');
    }
  };

  const startCamera = async () => {
    try {
      const s = await navigator.mediaDevices.getUserMedia({
        video: { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: 'user' }
      });
      setStream(s);
      if (videoRef.current) {
        videoRef.current.srcObject = s;
        videoRef.current.style.transform = 'scaleX(-1)';
      }
      setStep('capture');
    } catch (e) {
      setQualityMsg('Camera access denied. Please allow camera access.');
    }
  };

  const capturePhoto = () => {
    const video = videoRef.current;
    const canvas = canvasRef.current;
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
    if (avg < 35) { setQualityMsg('⚠️ Too dark — move to a brighter area.'); return; }
    if (avg > 240) { setQualityMsg('⚠️ Too bright — reduce glare.'); return; }

    setQualityMsg('');
    // Scale down
    const scaled = document.createElement('canvas');
    scaled.width  = 480;
    scaled.height = Math.round(canvas.height * 480 / canvas.width);
    scaled.getContext('2d').drawImage(canvas, 0, 0, scaled.width, scaled.height);
    const base64 = scaled.toDataURL('image/jpeg', 0.85).split(',')[1];

    setFaceBase64(base64);
    setFaceCaptured(true);
    if (stream) { stream.getTracks().forEach(t => t.stop()); setStream(null); }
  };

  const retake = () => {
    setFaceBase64(null);
    setFaceCaptured(false);
    setQualityMsg('');
    startCamera();
  };

  const submitVerify = async () => {
    if (!faceBase64 || submitting) return;
    setSubmitting(true);
    try {
      const r = await fetch(`${API}/api/abroad-verify/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, face_base64: faceBase64 })
      });
      const d = await r.json();
      setResult(d);
      setStep('result');
    } catch (e) {
      setResult({ success: false, message: 'Network error. Please try again.' });
      setStep('result');
    } finally {
      setSubmitting(false);
    }
  };

  const fmtRWF = (n) => Number(n || 0).toLocaleString() + ' RWF';

  return (
    <div className="min-h-screen flex items-center justify-center p-5 bg-slate-50">
      {/* Background pattern */}
      <div className="fixed inset-0 pointer-events-none opacity-100" style={{
        backgroundImage: 'linear-gradient(rgba(5,150,105,.04) 1px, transparent 1px), linear-gradient(90deg, rgba(5,150,105,.04) 1px, transparent 1px)',
        backgroundSize: '40px 40px'
      }} />

      <div className="w-full max-w-[460px] relative z-10">
        {/* Brand */}
        <div className="text-center mb-6">
          <div className="w-14 h-14 bg-gradient-to-br from-emerald-500 to-sky-500 rounded-2xl inline-flex items-center justify-center mb-3 shadow-lg shadow-emerald-500/30">
            <Shield className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-2xl font-bold bg-gradient-to-r from-emerald-500 to-sky-500 bg-clip-text text-transparent">
            MoMo Shield
          </h1>
          <p className="text-sm text-slate-500 mt-1">Abroad Transfer Verification</p>
        </div>

        <div className="bg-white border-2 border-slate-300 rounded-3xl overflow-hidden shadow-xl">

          {/* ── LOADING ── */}
          {step === 'loading' && (
            <div className="p-10 text-center text-slate-500">
              <div className="w-8 h-8 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
              Loading transfer details…
            </div>
          )}

          {/* ── INFO — show transfer details, ask to proceed ── */}
          {step === 'info' && info && (
            <div>
              <div className="bg-amber-50 border-b border-amber-200 p-5 text-center">
                <Plane className="w-8 h-8 text-amber-500 mx-auto mb-2" />
                <h2 className="text-base font-bold text-amber-700">Transfer While You Are Abroad</h2>
                <p className="text-xs text-amber-600 mt-1">
                  Hello <strong>{info.owner_name}</strong> — someone tried to send money
                  from your account while you are in <strong>{info.destination}</strong>.
                </p>
              </div>

              <div className="p-6">
                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 mb-5 text-sm space-y-2">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Your Phone</span>
                    <span className="font-mono font-semibold">{info.owner_phone}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Recipient</span>
                    <span className="font-mono font-semibold">{info.recipient_phone}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Amount</span>
                    <span className="font-semibold text-emerald-600">{fmtRWF(info.amount)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Fee</span>
                    <span>{fmtRWF(info.fee)}</span>
                  </div>
                  <div className="flex justify-between border-t border-slate-200 pt-2">
                    <span className="text-slate-500 font-semibold">Total Deducted</span>
                    <span className="font-bold text-slate-800">{fmtRWF(info.total)}</span>
                  </div>
                </div>

                <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-3 mb-5 text-xs text-emerald-700">
                  <strong>If this was you:</strong> Click "Approve" and scan your face to confirm.
                  The money will be sent immediately after your face matches.
                </div>
                <div className="bg-rose-50 border border-rose-200 rounded-xl p-3 mb-5 text-xs text-rose-700">
                  <strong>If you did NOT authorise this:</strong> Close this page. The transfer
                  will automatically be blocked after 24 hours.
                </div>

                <button
                  onClick={startCamera}
                  className="w-full py-3 bg-gradient-to-br from-emerald-500 to-sky-500 text-white rounded-[14px] font-bold text-sm hover:shadow-lg hover:-translate-y-0.5 transition-all flex items-center justify-center gap-2"
                >
                  <Camera className="w-4 h-4" />
                  Approve — Scan My Face
                </button>
              </div>
            </div>
          )}

          {/* ── FACE CAPTURE ── */}
          {step === 'capture' && (
            <div className="p-6">
              <h2 className="text-base font-bold text-center text-slate-800 mb-1">Face Verification</h2>
              <p className="text-xs text-center text-slate-500 mb-4">
                Look directly at the camera with your full face visible
              </p>

              {qualityMsg && (
                <div className="bg-amber-50 border border-amber-200 rounded-xl p-3 text-xs text-amber-700 mb-3 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                  {qualityMsg}
                </div>
              )}

              <div className="relative rounded-xl overflow-hidden border-2 border-slate-300 mb-4 bg-black">
                <video
                  ref={videoRef}
                  autoPlay
                  muted
                  playsInline
                  className={`w-full ${faceCaptured ? 'hidden' : 'block'}`}
                />
                {faceCaptured && faceBase64 && (
                  <img
                    src={`data:image/jpeg;base64,${faceBase64}`}
                    alt="Captured face"
                    className="w-full"
                  />
                )}
                {/* Face guide overlay */}
                {!faceCaptured && (
                  <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                    <div className="w-40 h-48 border-2 border-emerald-400 border-dashed rounded-full opacity-50" />
                  </div>
                )}
              </div>
              <canvas ref={canvasRef} className="hidden" />

              {!faceCaptured ? (
                <button
                  onClick={capturePhoto}
                  className="w-full py-3 bg-gradient-to-br from-emerald-500 to-sky-500 text-white rounded-[14px] font-bold text-sm hover:shadow-lg transition-all flex items-center justify-center gap-2"
                >
                  <Camera className="w-4 h-4" />
                  Capture Photo
                </button>
              ) : (
                <div className="space-y-2">
                  <button
                    onClick={submitVerify}
                    disabled={submitting}
                    className="w-full py-3 bg-gradient-to-br from-emerald-500 to-sky-500 text-white rounded-[14px] font-bold text-sm hover:shadow-lg transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                  >
                    {submitting ? (
                      <><div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" /> Verifying…</>
                    ) : (
                      <><Check className="w-4 h-4" /> Confirm & Approve Transfer</>
                    )}
                  </button>
                  <button
                    onClick={retake}
                    disabled={submitting}
                    className="w-full py-2.5 bg-transparent text-emerald-600 border border-emerald-500 rounded-[14px] font-semibold text-sm hover:bg-emerald-50 transition-all flex items-center justify-center gap-2"
                  >
                    <RefreshCw className="w-4 h-4" />
                    Retake
                  </button>
                </div>
              )}
            </div>
          )}

          {/* ── RESULT ── */}
          {step === 'result' && (
            <div className="p-8 text-center">
              {result?.success || error === '' && result?.success ? (
                <>
                  <div className="w-16 h-16 bg-emerald-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <Check className="w-8 h-8 text-emerald-500" />
                  </div>
                  <h2 className="text-lg font-bold text-emerald-600 mb-2">Transfer Approved!</h2>
                  <p className="text-sm text-slate-600">{result.message}</p>
                  {result.reference && (
                    <p className="text-xs text-slate-400 mt-2 font-mono">Ref: {result.reference}</p>
                  )}
                </>
              ) : (
                <>
                  <div className={`w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4 ${
                    result?.action === 'BLOCKED' ? 'bg-rose-100' : 'bg-amber-100'
                  }`}>
                    <AlertTriangle className={`w-8 h-8 ${
                      result?.action === 'BLOCKED' ? 'text-rose-500' : 'text-amber-500'
                    }`} />
                  </div>
                  <h2 className={`text-lg font-bold mb-2 ${
                    result?.action === 'BLOCKED' ? 'text-rose-600' : 'text-amber-600'
                  }`}>
                    {result?.action === 'BLOCKED' ? 'Transfer Blocked' :
                     result?.status === 'expired' ? 'Link Expired' : 'Verification Failed'}
                  </h2>
                  <p className="text-sm text-slate-600">
                    {result?.message || error || 'Something went wrong.'}
                  </p>
                  {result?.action === 'BLOCKED' && (
                    <p className="text-xs text-slate-400 mt-3">
                      If you believe this is an error, please contact MoMo Shield support.
                    </p>
                  )}
                </>
              )}
            </div>
          )}
        </div>

        <p className="text-center text-xs text-slate-400 mt-4">
          MoMo Shield — AI-Powered Mobile Money Fraud Detection
        </p>
      </div>
    </div>
  );
}
