'use client'
import React from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'

const Navbar = () => {
  const pathname = usePathname()
  
  const navItems = [
    { name: 'ANALYSIS.EXE', href: '/dashboard/analysis', icon: '🔍' },
    { name: 'MITRE_ATTACK.DB', href: '/dashboard/mitre', icon: '🛡️' },
    { name: 'DASHBOARD.SYS', href: '/dashboard', icon: '📊' },
  ]

  return (
    <div className='bg-black/95 backdrop-blur-sm border-b border-green-500/30 p-4 sticky top-0 z-50 font-mono'>
      <div className='flex items-center justify-between max-w-7xl mx-auto'>
        <div className='flex items-center space-x-3'>
          <div className='w-8 h-8 bg-black border-2 border-green-500 flex items-center justify-center'>
            <span className='text-green-400 font-bold text-sm'>F</span>
          </div>
          <h1 className='text-xl font-bold text-green-400 tracking-wider'>
            [FORENSIQ_V2.0]
          </h1>
        </div>
        
        <nav className='flex space-x-2'>
          {navItems.map((item) => {
            const isActive = pathname === item.href
            return (
              <Link
                key={item.name}
                href={item.href}
                className={`flex items-center space-x-2 px-4 py-2 border transition-all duration-200 hover:shadow-[0_0_10px_rgba(0,255,150,0.3)] ${
                  isActive
                    ? 'bg-green-500/20 border-green-400 text-green-400'
                    : 'bg-black/50 border-green-500/30 text-green-500 hover:text-green-400 hover:border-green-400'
                }`}
              >
                <span>{item.icon}</span>
                <span className='font-medium text-sm'>&gt; {item.name}</span>
              </Link>
            )
          })}
        </nav>
        
        <div className='flex items-center space-x-4'>
          <div className='flex items-center space-x-2 text-green-400 text-sm'>
            <span className='animate-pulse'>●</span>
            <span>[ONLINE]</span>
          </div>
          <div className='w-8 h-8 bg-black border border-green-500/50 flex items-center justify-center'>
            <span className='text-green-400 text-sm'>👤</span>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Navbar
