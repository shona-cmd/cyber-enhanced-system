import React, { useState } from 'react';
import { Shield, Lock, Eye, EyeOff, AlertCircle, CheckCircle2, Wifi, Server, Database, Activity } from 'lucide-react';

export default function MTACLogin() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = () => {
    setIsLoading(true);
    setError('');
    
    setTimeout(() => {
      if (username === 'mtac-admin' && password === 'Mtac2025!') {
        alert('Login Successful! Welcome to MTAC Secure System.');
      } else {
        setError('Invalid credentials. Please try again.');
      }
      setIsLoading(false);
    }, 1500);
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleSubmit();
    }
  };

  const features = [
    { icon: Shield, title: 'Military-Grade Encryption', desc: 'AES-256 bit encryption for all data transmissions' },
    { icon: Server, title: 'Real-Time Monitoring', desc: 'Monitor all IoT devices in real-time with instant alerts' },
    { icon: Database, title: 'Secure Data Storage', desc: 'Encrypted cloud storage with automated backups' },
    { icon: Activity, title: 'Threat Detection', desc: 'AI-powered anomaly detection and threat prevention' }
  ];

  const stats = [
    { value: '99.9%', label: 'Uptime' },
    { value: '10K+', label: 'Devices Protected' },
    { value: '<10ms', label: 'Response Time' },
    { value: '24/7', label: 'Support' }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex items-center justify-center p-4 relative overflow-hidden">
      {/* Animated background elements */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute w-96 h-96 bg-blue-500/10 rounded-full blur-3xl -top-48 -left-48 animate-pulse"></div>
        <div className="absolute w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl -bottom-48 -right-48 animate-pulse delay-700"></div>
      </div>

      {/* Grid overlay */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(6,182,212,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(6,182,212,0.03)_1px,transparent_1px)] bg-[size:50px_50px]"></div>

      <div className="w-full max-w-6xl relative z-10">
        <div className="grid md:grid-cols-2 gap-8 items-center">
          {/* Left side - Branding and Info */}
          <div className="text-white space-y-8 order-2 md:order-1">
            {/* Logo and Title */}
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-16 h-16 bg-gradient-to-br from-cyan-400 to-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-cyan-500/50">
                  <Shield className="w-10 h-10 text-white" />
                </div>
                <div>
                  <h1 className="text-3xl font-bold">NaashonSecureIoT</h1>
                  <p className="text-cyan-300 text-sm">Military-Grade Security Platform</p>
                </div>
              </div>
              <h2 className="text-4xl font-bold bg-gradient-to-r from-cyan-300 to-blue-300 bg-clip-text text-transparent">
                MTAC SECURE ACCESS
              </h2>
              <p className="text-slate-300 text-lg">
                Enterprise-grade IoT security management platform with real-time threat detection and comprehensive device monitoring.
              </p>
            </div>

            {/* Features Grid */}
            <div className="grid grid-cols-2 gap-4">
              {features.map((feature, idx) => (
                <div key={idx} className="bg-white/5 backdrop-blur-sm border border-white/10 rounded-lg p-4 hover:bg-white/10 transition-all duration-300">
                  <feature.icon className="w-8 h-8 text-cyan-400 mb-2" />
                  <h3 className="font-semibold text-sm mb-1">{feature.title}</h3>
                  <p className="text-xs text-slate-400">{feature.desc}</p>
                </div>
              ))}
            </div>

            {/* Stats */}
            <div className="grid grid-cols-4 gap-4">
              {stats.map((stat, idx) => (
                <div key={idx} className="text-center">
                  <div className="text-2xl font-bold text-cyan-400">{stat.value}</div>
                  <div className="text-xs text-slate-400">{stat.label}</div>
                </div>
              ))}
            </div>

            {/* Trust Badges */}
            <div className="flex items-center gap-4 pt-4 border-t border-white/10">
              <CheckCircle2 className="w-5 h-5 text-green-400" />
              <span className="text-sm text-slate-300">ISO 27001 Certified</span>
              <CheckCircle2 className="w-5 h-5 text-green-400" />
              <span className="text-sm text-slate-300">SOC 2 Type II</span>
            </div>
          </div>

          {/* Right side - Login Form */}
          <div className="order-1 md:order-2">
            <div className="bg-white/10 backdrop-blur-xl border border-white/20 rounded-2xl p-8 shadow-2xl">
              {/* Form Header */}
              <div className="text-center mb-8">
                <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-cyan-400 to-blue-600 rounded-full mb-4 shadow-lg shadow-cyan-500/50">
                  <Lock className="w-8 h-8 text-white" />
                </div>
                <h3 className="text-2xl font-bold text-white mb-2">Secure Login</h3>
                <p className="text-slate-300 text-sm">Enter your credentials to access the platform</p>
              </div>

              {/* Demo Credentials Banner */}
              <div className="bg-blue-500/20 border border-blue-400/30 rounded-lg p-4 mb-6">
                <div className="flex items-start gap-3">
                  <AlertCircle className="w-5 h-5 text-blue-300 flex-shrink-0 mt-0.5" />
                  <div className="text-sm">
                    <p className="text-blue-200 font-semibold mb-1">Demo Credentials</p>
                    <p className="text-blue-100">Username: <span className="font-mono bg-blue-900/30 px-2 py-0.5 rounded">mtac-admin</span></p>
                    <p className="text-blue-100">Password: <span className="font-mono bg-blue-900/30 px-2 py-0.5 rounded">Mtac2025!</span></p>
                  </div>
                </div>
              </div>

              {/* Error Message */}
              {error && (
                <div className="bg-red-500/20 border border-red-400/30 rounded-lg p-3 mb-6 flex items-center gap-2">
                  <AlertCircle className="w-5 h-5 text-red-300" />
                  <p className="text-red-200 text-sm">{error}</p>
                </div>
              )}

              {/* Login Form */}
              <div className="space-y-6">
                {/* Username Field */}
                <div>
                  <label className="block text-white text-sm font-medium mb-2">
                    Username
                  </label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    onKeyPress={handleKeyPress}
                    className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:border-transparent transition-all"
                    placeholder="Enter your username"
                  />
                </div>

                {/* Password Field */}
                <div>
                  <label className="block text-white text-sm font-medium mb-2">
                    Password
                  </label>
                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      onKeyPress={handleKeyPress}
                      className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:border-transparent transition-all pr-12"
                      placeholder="Enter your password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white transition-colors"
                    >
                      {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                    </button>
                  </div>
                </div>

                {/* Remember Me & Forgot Password */}
                <div className="flex items-center justify-between text-sm">
                  <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                    <input type="checkbox" className="w-4 h-4 rounded border-white/20 bg-white/10 text-cyan-500 focus:ring-cyan-400" />
                    Remember me
                  </label>
                  <button className="text-cyan-400 hover:text-cyan-300 transition-colors">
                    Forgot password?
                  </button>
                </div>

                {/* Submit Button */}
                <button
                  onClick={handleSubmit}
                  disabled={isLoading}
                  className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-600 hover:to-blue-700 text-white font-semibold py-3 px-6 rounded-lg shadow-lg shadow-cyan-500/50 hover:shadow-cyan-500/70 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  {isLoading ? (
                    <>
                      <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                      Authenticating...
                    </>
                  ) : (
                    <>
                      <Shield className="w-5 h-5" />
                      Secure Login
                    </>
                  )}
                </button>
              </div>

              {/* Footer Links */}
              <div className="mt-8 pt-6 border-t border-white/10 text-center">
                <p className="text-slate-400 text-sm">
                  Need access? <button className="text-cyan-400 hover:text-cyan-300 transition-colors">Contact Administrator</button>
                </p>
              </div>
            </div>

            {/* Security Notice */}
            <div className="mt-4 text-center">
              <p className="text-slate-400 text-xs flex items-center justify-center gap-2">
                <Wifi className="w-4 h-4" />
                Secure connection established • All data encrypted
              </p>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-12 text-center text-slate-400 text-sm">
          <p>© 2025 NaashonSecureIoT. All rights reserved. | <button className="text-cyan-400 hover:text-cyan-300">Privacy Policy</button> | <button className="text-cyan-400 hover:text-cyan-300">Terms of Service</button></p>
        </div>
      </div>
    </div>
  );
}
