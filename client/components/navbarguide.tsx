'use client'
import React, { useState } from 'react';
import { Menu, X, Terminal, Shield, Book } from 'lucide-react';
import Link from 'next/link';

const Navbar: React.FC = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  

  const navItems = [
    { 
      name: 'dashboard', 
      shortName: 'DASH',
      href: '/dashboard', 
      icon: <Shield className="w-4 h-4" /> 
    },
    { 
      name: 'cli_guide',
      shortName: 'GUIDE',
      href: '/guide', 
      icon: <Book className="w-4 h-4" /> 
    }
  ];

  const isActiveLink = (href: string) => {
    return window.location.pathname === href || (href === '/dashboard' && window.location.pathname === '/');
  };

  return (
    <nav className="relative bg-black/90 backdrop-blur-sm border-b border-green-500/30 font-mono">
      <div className="container mx-auto px-4 sm:px-6">
        <div className="flex items-center justify-between h-16 sm:h-20">
          {/* Logo */}
          <Link href="/dashboard" className="flex items-center space-x-2 sm:space-x-3 text-green-400 hover:text-cyan-400 transition-colors">
          <Link href="/dashboard" className="flex items-center space-x-2 sm:space-x-3 text-green-400 hover:text-cyan-400 transition-colors">
            <Terminal className="w-6 h-6 sm:w-8 sm:h-8" />
            <span className="text-lg sm:text-xl font-bold tracking-wider">
              <span className="hidden sm:inline">FORENSIQ</span>
              <span className="sm:hidden">FQ</span>
            </span>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-8">
            {navItems.map((item) => (
              <Link
                key={item.name}
                href={item.href}
                href={item.href}
                className={`flex items-center space-x-2 px-4 py-2 transition-all duration-300 border ${
                  isActiveLink(item.href)
                    ? 'border-cyan-400 text-cyan-400 bg-cyan-500/10'
                    : 'border-transparent text-green-400 hover:text-cyan-400 hover:border-cyan-400/30'
                }`}
              >
                {item.icon}
                <span>[{item.name}]</span>
              </Link>
            ))}
          </div>

          {/* Mobile Menu Button */}
          <button
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            className="md:hidden p-2 text-green-400 hover:text-cyan-400 transition-colors"
          >
            {isMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>

        {/* Mobile Navigation */}
        {isMenuOpen && (
          <div className="md:hidden absolute top-full left-0 right-0 bg-black/95 backdrop-blur-sm border-b border-green-500/30 z-50">
            <div className="px-4 py-4 space-y-3">
              {navItems.map((item) => (
                <Link
                  key={item.name}
                  href={item.href}
                  href={item.href}
                  className={`flex items-center space-x-3 px-4 py-3 transition-all duration-300 border ${
                    isActiveLink(item.href)
                      ? 'border-cyan-400 text-cyan-400 bg-cyan-500/10'
                      : 'border-transparent text-green-400 hover:text-cyan-400 hover:border-cyan-400/30'
                  }`}
                  onClick={() => setIsMenuOpen(false)}
                >
                  {item.icon}
                  <span>[{item.shortName}]</span>
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    </nav>
  );
};

export default Navbar;