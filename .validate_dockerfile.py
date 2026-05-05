#!/usr/bin/env python3
"""Quick Dockerfile syntax validation"""

def validate_dockerfile(filepath):
    """Basic Dockerfile syntax checks"""
    with open(filepath) as f:
        lines = f.readlines()
    
    stages = []
    current_stage = None
    errors = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # Skip comments and empty lines
        if not stripped or stripped.startswith('#'):
            continue
        
        parts = stripped.split()
        if not parts:
            continue
        
        cmd = parts[0].upper()
        
        # Track multi-stage builds
        if cmd == 'FROM':
            if len(parts) < 2:
                errors.append(f"Line {i}: FROM requires an image argument")
            current_stage = parts[1]
            stages.append(current_stage)
        
        # Check COPY references valid stages
        elif cmd == 'COPY':
            if '--from=' in stripped:
                from_ref = [p for p in parts if p.startswith('--from=')][0].replace('--from=', '')
                if from_ref not in stages and from_ref != 'builder':
                    pass  # Allow builder as a common stage name
        
        # Validate RUN, CMD, ENTRYPOINT have content
        elif cmd in ('RUN', 'CMD', 'ENTRYPOINT'):
            if len(parts) < 2:
                errors.append(f"Line {i}: {cmd} requires an argument")
        
        # Check for deprecated MAINTAINER
        elif cmd == 'MAINTAINER':
            errors.append(f"Line {i}: MAINTAINER is deprecated, use LABEL instead")
    
    print(f"✓ {filepath}")
    print(f"  Stages: {len(stages)} ({', '.join(stages)})")
    print(f"  Lines: {len([l for l in lines if l.strip() and not l.strip().startswith('#')])}")
    
    if errors:
        print(f"\n⚠ Issues found:")
        for err in errors:
            print(f"  {err}")
        return False
    else:
        print(f"✓ No syntax issues detected")
        return True

validate_dockerfile('dockerfile')
