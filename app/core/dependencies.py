import re
import logging
from typing import List, Dict, Any, Optional
import aiohttp
import asyncio
from bs4 import BeautifulSoup
from functools import lru_cache
import time
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Rate limiting for NVD API
RATE_LIMIT = 5  # requests per second
last_request_time = 0

@lru_cache(maxsize=1000)
def get_cached_vulnerability(package: str, version: str) -> Optional[List[Dict[str, Any]]]:
    """Get cached vulnerability results."""
    return None

def cache_vulnerability(package: str, version: str, vulnerabilities: List[Dict[str, Any]]):
    """Cache vulnerability results."""
    get_cached_vulnerability.cache_info()

async def check_dependencies(code: str, language: str) -> List[Dict[str, Any]]:
    """Check for vulnerable dependencies in the code."""
    try:
        # Extract dependencies based on language
        dependencies = extract_dependencies(code, language)
        if not dependencies:
            logger.info(f"No dependencies found for language: {language}")
            return []

        # Check each dependency for vulnerabilities
        vulnerabilities = []
        async with aiohttp.ClientSession() as session:
            tasks = []
            for dep in dependencies:
                tasks.append(check_dependency(session, dep))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Error checking dependency: {result}")
                    continue
                if result:
                    vulnerabilities.extend(result)

        return vulnerabilities

    except Exception as e:
        logger.error(f"Error checking dependencies: {e}")
        return []

def extract_dependencies(code: str, language: str) -> List[Dict[str, str]]:
    """Extract dependencies from code based on language."""
    dependencies = []
    
    try:
        if language == 'python':
            # Extract from requirements.txt or setup.py
            requirements_pattern = r'^([a-zA-Z0-9_-]+)(?:[<>=!~]+)([0-9.]+)'
            setup_pattern = r'install_requires\s*=\s*\[(.*?)\]'
            
            # Check for requirements.txt format
            for line in code.split('\n'):
                match = re.match(requirements_pattern, line.strip())
                if match:
                    dependencies.append({
                        'package': match.group(1).lower(),
                        'version': match.group(2)
                    })
            
            # Check for setup.py format
            setup_match = re.search(setup_pattern, code, re.DOTALL)
            if setup_match:
                deps_str = setup_match.group(1)
                for dep in re.finditer(r'"([^"]+)(?:[<>=!~]+)([0-9.]+)"', deps_str):
                    dependencies.append({
                        'package': dep.group(1).lower(),
                        'version': dep.group(2)
                    })
                    
        elif language == 'javascript':
            # Extract from package.json
            package_pattern = r'"([^"]+)":\s*"([^"]+)"'
            dev_deps_pattern = r'"devDependencies":\s*{([^}]+)}'
            
            # Check main dependencies
            for line in code.split('\n'):
                match = re.search(package_pattern, line)
                if match and not any(x in match.group(1) for x in ['name', 'version', 'description']):
                    dependencies.append({
                        'package': match.group(1).lower(),
                        'version': match.group(2)
                    })
            
            # Check devDependencies
            dev_deps_match = re.search(dev_deps_pattern, code, re.DOTALL)
            if dev_deps_match:
                for dep in re.finditer(package_pattern, dev_deps_match.group(1)):
                    dependencies.append({
                        'package': dep.group(1).lower(),
                        'version': dep.group(2)
                    })
                    
        elif language == 'java':
            # Extract from pom.xml or build.gradle
            dependency_pattern = r'<dependency>.*?<artifactId>([^<]+)</artifactId>.*?<version>([^<]+)</version>'
            gradle_pattern = r"implementation\s+['\"]([^'\"]+):([^'\"]+)['\"]"
            
            # Check Maven dependencies
            for match in re.finditer(dependency_pattern, code, re.DOTALL):
                dependencies.append({
                    'package': match.group(1).lower(),
                    'version': match.group(2)
                })
            
            # Check Gradle dependencies
            for match in re.finditer(gradle_pattern, code):
                dependencies.append({
                    'package': match.group(1).lower(),
                    'version': match.group(2)
                })
                
    except Exception as e:
        logger.error(f"Error extracting dependencies: {e}")
    
    return dependencies

async def check_dependency(session: aiohttp.ClientSession, dependency: Dict[str, str]) -> List[Dict[str, Any]]:
    """Check a single dependency for vulnerabilities with rate limiting."""
    try:
        package = dependency['package']
        version = dependency['version']
        
        # Check cache first
        cached_result = get_cached_vulnerability(package, version)
        if cached_result is not None:
            return cached_result
        
        # Rate limiting
        global last_request_time
        current_time = time.time()
        if current_time - last_request_time < 1.0 / RATE_LIMIT:
            await asyncio.sleep(1.0 / RATE_LIMIT - (current_time - last_request_time))
        last_request_time = time.time()
        
        # Check NVD database
        nvd_url = f"https://nvd.nist.gov/vuln/search/results?query={package}&version={version}"
        async with session.get(nvd_url, timeout=10) as response:
            if response.status == 200:
                html = await response.text()
                soup = BeautifulSoup(html, 'lxml')
                
                vulnerabilities = []
                for vuln in soup.find_all('tr', class_='vulnerability-row'):
                    try:
                        vuln_id = vuln.find('a', class_='vulnerability-id').text.strip()
                        description = vuln.find('p', class_='vulnerability-description').text.strip()
                        severity = vuln.find('span', class_='severity').text.strip()
                        
                        vulnerabilities.append({
                            'package': package,
                            'version': version,
                            'vulnerability': f"{vuln_id}: {description}",
                            'severity': severity,
                            'fix': f"Update {package} to a newer version",
                            'timestamp': datetime.now().isoformat()
                        })
                    except Exception as e:
                        logger.error(f"Error parsing vulnerability: {e}")
                        continue
                
                # Cache the results
                cache_vulnerability(package, version, vulnerabilities)
                return vulnerabilities
                
    except asyncio.TimeoutError:
        logger.error(f"Timeout checking dependency {dependency}")
    except Exception as e:
        logger.error(f"Error checking dependency {dependency}: {e}")
    
    return [] 