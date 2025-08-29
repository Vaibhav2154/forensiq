'use client'
import React, { useState, useEffect } from 'react'
import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'


const Navbar = () => {
  const pathname = usePathname()
  const router = useRouter()
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  const [isMobile, setIsMobile] = useState(false)

  const navItems = [
    { name: 'DASHBOARD.SYS', href: '/dashboard', icon: '📊', shortName: 'DASH' },
    { name: 'MITRE_ATTACK.DB', href: '/dashboard/mitre', icon: '🛡️', shortName: 'MITRE' },
    { name: 'ANALYSIS.EXE', href: '/dashboard/analysis', icon: '🔍', shortName: 'ANALYZE' },
  ]

  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768)
    }
    
    checkMobile()
    window.addEventListener('resize', checkMobile)
    
    return () => window.removeEventListener('resize', checkMobile)
  }, [])

  // Close mobile menu when clicking outside or on link
  useEffect(() => {
    const handleClickOutside = () => {
      setIsMobileMenuOpen(false)
    }

    if (isMobileMenuOpen) {
      document.addEventListener('click', handleClickOutside)
    }

    return () => {
      document.removeEventListener('click', handleClickOutside)
    }
  }, [isMobileMenuOpen])

  const toggleMobileMenu = (e: React.MouseEvent<HTMLButtonElement>) => {
    e.stopPropagation()
    setIsMobileMenuOpen(!isMobileMenuOpen)
  }

  return (
    <div className='bg-black/95 backdrop-blur-sm border-b border-green-500/30 sticky top-0 z-50 font-mono'>
      <div className='px-3 sm:px-4 md:px-6 py-3 sm:py-4'>
        <div className='flex items-center justify-between max-w-7xl mx-auto'>
          {/* Logo Section */}
          <div className='flex items-center space-x-2 sm:space-x-3 flex-shrink-0'>
            <div className='w-6 h-6 sm:w-8 sm:h-8 bg-black border-2 border-green-500 flex items-center justify-center'>
              <span className='text-green-400 font-bold text-xs sm:text-sm'>F</span>
            </div>
            <h1 className='text-sm sm:text-lg md:text-xl font-bold text-green-400 tracking-wider'>
              <span className='hidden sm:inline'>[FORENSIQ_V2.0]</span>
              <span className='sm:hidden'>[FORENSIQ]</span>
            </h1>
          </div>

          {/* Desktop Navigation */}
          <nav className='hidden md:flex space-x-1 lg:space-x-2'>
            {navItems.map((item) => {
              const isActive = pathname === item.href
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  className={`flex items-center space-x-2 px-3 lg:px-4 py-2 border transition-all duration-200 hover:shadow-[0_0_10px_rgba(0,255,150,0.3)] ${
                    isActive
                      ? 'bg-green-500/20 border-green-400 text-green-400'
                      : 'bg-black/50 border-green-500/30 text-green-500 hover:text-green-400 hover:border-green-400'
                  }`}
                >
                  <span className='text-sm'>{item.icon}</span>
                  <span className='font-medium text-xs lg:text-sm whitespace-nowrap'>&gt; {item.name}</span>
                </Link>
              )
            })}
          </nav>

          {/* Mobile Navigation Button & Status */}
          <div className='flex items-center space-x-2 sm:space-x-4'>
            {/* Status - Hidden on very small screens */}
            <div className='hidden xs:flex items-center space-x-1 sm:space-x-2 text-green-400 text-xs sm:text-sm'>
              <span className='animate-pulse'>●</span>
              <span className='hidden sm:inline'>[ONLINE]</span>
              <span className='sm:hidden'>[ON]</span>
            </div>

            {/* User Icon */}
            <div className='w-6 h-6 sm:w-8 sm:h-8 bg-black border border-green-500/50 flex items-center justify-center'>
              <span className='text-green-400 text-xs sm:text-sm' onClick={()=>router.push('/profileupdate')}>👤</span>
            </div>

            {/* Mobile Menu Button */}
            <button
              onClick={toggleMobileMenu}
              className='md:hidden w-8 h-8 bg-black border-2 border-green-500/50 flex items-center justify-center hover:border-green-400 transition-colors'
              aria-label="Toggle mobile menu"
            >
              <div className='flex flex-col space-y-1'>
                <div className={`w-3 h-0.5 bg-green-400 transition-all duration-200 ${isMobileMenuOpen ? 'rotate-45 translate-y-1' : ''}`}></div>
                <div className={`w-3 h-0.5 bg-green-400 transition-all duration-200 ${isMobileMenuOpen ? 'opacity-0' : ''}`}></div>
                <div className={`w-3 h-0.5 bg-green-400 transition-all duration-200 ${isMobileMenuOpen ? '-rotate-45 -translate-y-1' : ''}`}></div>
              </div>
            </button>
          </div>
        </div>

        {/* Mobile Navigation Menu */}
        <div className={`md:hidden transition-all duration-300 ease-in-out overflow-hidden ${
          isMobileMenuOpen ? 'max-h-96 opacity-100' : 'max-h-0 opacity-0'
        }`}>
          <nav className='pt-4 pb-2 space-y-2'>
            {navItems.map((item) => {
              const isActive = pathname === item.href
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  onClick={() => setIsMobileMenuOpen(false)}
                  className={`flex items-center justify-between w-full px-3 py-3 border transition-all duration-200 hover:shadow-[0_0_10px_rgba(0,255,150,0.3)] ${
                    isActive
                      ? 'bg-green-500/20 border-green-400 text-green-400'
                      : 'bg-black/50 border-green-500/30 text-green-500 hover:text-green-400 hover:border-green-400'
                  }`}
                >
                  <div className='flex items-center space-x-3'>
                    <span>{item.icon}</span>
                    <span className='font-medium text-sm'>
                      &gt; <span className='hidden xs:inline'>{item.name}</span>
                      <span className='xs:hidden'>{item.shortName}</span>
                    </span>
                  </div>
                  {isActive && (
                    <div className='w-2 h-2 bg-green-400 rounded-full animate-pulse'></div>
                  )}
                </Link>
              )
            })}
          </nav>
          
          {/* Mobile Menu Footer */}
          <div className='pt-3 mt-3 border-t border-green-500/30'>
            <div className='flex items-center justify-between text-green-400 text-xs'>
              <span>[FORENSIQ_MOBILE_v2.0]</span>
              <div className='flex items-center space-x-2'>
                <span className='animate-pulse'>●</span>
                <span>[SECURE_CONNECTION]</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Custom styles for extra small screens */}
      <style jsx>{`
        @media (min-width: 475px) {
          .xs\\:flex {
            display: flex;
          }
          .xs\\:inline {
            display: inline;
          }
          .xs\\:hidden {
            display: none;
          }
        }
        
        @media (max-width: 474px) {
          .xs\\:flex {
            display: none;
          }
          .xs\\:inline {
            display: none;
          }
          .xs\\:hidden {
            display: inline;
          }
        }
      `}</style>
    </div>
  )
}

export default Navbar