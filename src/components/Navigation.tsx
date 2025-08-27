import React from 'react';
import { DivideIcon as LucideIcon } from 'lucide-react';

interface Section {
  id: string;
  title: string;
  icon: LucideIcon;
}

interface NavigationProps {
  sections: Section[];
  activeSection: string;
  onSectionChange: (section: string) => void;
}

export function Navigation({ sections, activeSection, onSectionChange }: NavigationProps) {
  return (
    <nav className="bg-white rounded-lg shadow-sm border border-slate-200 p-4 sticky top-8">
      <h3 className="font-semibold text-slate-700 mb-4">Documentation Sections</h3>
      <ul className="space-y-2">
        {sections.map((section) => {
          const Icon = section.icon;
          return (
            <li key={section.id}>
              <button
                onClick={() => onSectionChange(section.id)}
                className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-left transition-colors ${
                  activeSection === section.id
                    ? 'bg-blue-100 text-blue-700 border border-blue-200'
                    : 'text-slate-600 hover:bg-slate-100'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span className="text-sm font-medium">{section.title}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}