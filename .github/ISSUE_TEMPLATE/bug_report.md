name: Bug Report  
description: Report problems or errors encountered during testing or operations.  
title: "[Bug] <Short Description>"  
labels: ["bug"]  
body:
  - type: (text area)  
    id: description  
    attributes:  
      label: Description  
      description: Describe the bug clearly.  
      placeholder: Describe the issue...  
    validations:  
      required: true  

  - type: (text area)  
    id: steps  
    attributes:  
      label: Steps to Reproduce  
      description: List steps to reproduce the issue.  
      placeholder: 1. Go to '...' 2. Click on '...' 3. See error  
    validations:  
      required: true  

  - type: (text area)  
    id: expected  
    attributes:  
      label: Expected Behavior  
      description: What did you expect to happen?  
    validations:  
      required: true  

  - type: (text area)  
    id: actual  
    attributes:  
      label: Actual Behavior  
      description: What actually happened?  
    validations:  
      required: true  
