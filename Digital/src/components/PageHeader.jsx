import React from "react";
import Icon from "./Icon";

const PageHeader = ({ icon, eyebrow, title, subtitle, children }) => (
  <header className="page-header">
    <div className="page-heading">
      {icon && (
        <div className="page-icon">
          <Icon name={icon} size={20} />
        </div>
      )}
      <div>
        {eyebrow && <div className="page-eyebrow">{eyebrow}</div>}
        <h1 className="page-title">{title}</h1>
        {subtitle && <p className="page-subtitle">{subtitle}</p>}
      </div>
    </div>
    {children && <div className="page-actions">{children}</div>}
  </header>
);

export default PageHeader;
