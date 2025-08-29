'use client'
import React from 'react'

const Navbar = () => {
  return (
    <div className='bg-black border-b border-green-400 p-4 flex items-center justify-between'>
      <nav className=' flex flex-1 justify space-x-4 '>
        <div>
          <p className='text-green-400 hover:border-2 border-green-400 shadow-green-300 px-5 py-2 rounded-lg hover:text-black hover:bg-green-400 transition-shadow '>Mitre</p>
        </div>
        <div>
          <p className='text-green-400 hover:border-2 border-green-400 shadow-green-300 px-5 py-2 rounded-lg hover:text-black hover:bg-green-400 transition-shadow'>Dashboard</p>
        </div>
      </nav>
    </div>
  )
}

export default Navbar
