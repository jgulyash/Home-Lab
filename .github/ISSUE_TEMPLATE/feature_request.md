name: Feature Request  
description: Suggest improvements or enhancements for the lab or documentation.  
title: "[Feature] <Short Description>"  
labels: ["enhancement"]  
body:  
  - type: (text area)  
    id: description  
    attributes:  
      label: Feature Description  
      description: Describe the feature you would like to request.  
      placeholder: Describe the feature...  
    validations:  
      required: true  

  - type: (drop down)  
    id: project  
    attributes:  
      label: Affected Project  
      options:  
        - General  
        - SOC Operations Simulation  
        - Endpoint Threat Hunting  
        - Penetration Testing Lab  
        - Malware Analysis  
        - AWS Cloud Security  
        - Dark Web Threat Intelligence  
        - LLM/ML Threat Detection  
    validations:  
      required: false  

  - type: (text area)  
    id: benefits  
    attributes:  
      label: Benefits  
      description: How does this feature improve your lab or workflow?  
