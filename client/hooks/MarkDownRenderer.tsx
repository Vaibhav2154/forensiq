'use client';

import React from 'react';
import ReactMarkdown from 'react-markdown';

interface Props {
  markdown: string;
}

const MarkdownRenderer: React.FC<Props> = ({ markdown }) => {
  return (
    <div className="mb-6">
      
      
        <div className="prose prose-invert text-sm">
          <ReactMarkdown>
            {markdown}
          </ReactMarkdown>
       
      </div>
    </div>
  );
};

export default MarkdownRenderer;
