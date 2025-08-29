import StepGuide from '@/components/stepguide'
import React from 'react'
import Navbar from '@/components/navbarguide'
import { BrowserRouter } from 'react-router-dom'


const page = () => {
  return (
    <div>
        <BrowserRouter>
    <Navbar/>
      <StepGuide/>
      </BrowserRouter>
      
    </div>
  )
}


export default page
