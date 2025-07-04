name: Project Task  
description: Track individual tasks related to cybersecurity projects.  
title: "[Task] <Short Description>"  
labels: ["project-task"]  
body:  
  - type: (text area)  
    id: description  
    attributes:  
      label: Description  
      description: Describe the task in detail.  
      placeholder: Explain the task clearly...  
    validations:  
      required: true  

  - type: (drop down)  
    id: project  
    attributes:  
      label: Related Project  
      options:  
        - SOC Operations Simulation  
        - Endpoint Threat Hunting  
        - Penetration Testing Lab  
        - Malware Analysis  
        - AWS Cloud Security  
        - Dark Web Threat Intelligence  
        - LLM/ML Threat Detection  
    validations:  
      required: true  

  - type: (drop down)  
    id: priority  
    attributes:  
      label: Priority  
      options:  
        - High  
        - Medium  
        - Low  
    validations:  
      required: false  

  - type: (text area)  
    id: acceptance  
    attributes:  
      label: Acceptance Criteria  
      description: Define what completion looks like for this task.  
      placeholder: List of criteria...  
