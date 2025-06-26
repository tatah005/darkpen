# Contributing to DarkPen

Thank you for your interest in contributing to DarkPen! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

### Reporting Bugs
- Use the GitHub issue tracker
- Include detailed steps to reproduce the bug
- Provide system information (OS, Python version, etc.)
- Include error messages and logs

### Suggesting Features
- Check existing issues first
- Provide clear description of the feature
- Explain the use case and benefits
- Consider implementation complexity

### Code Contributions
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Update documentation
6. Submit a pull request

## 🛠️ Development Setup

### Prerequisites
- Python 3.8+
- Git
- Kali Linux or similar (for testing)

### Local Development
```bash
# Clone your fork
git clone https://github.com/yourusername/darkpen.git
cd darkpen

# Install dependencies
pip3 install -r requirements.txt

# Install development dependencies
pip3 install -r requirements-dev.txt

# Run tests
python3 -m pytest tests/

# Run the application
python3 main.py
```

## 📝 Code Style

### Python
- Follow PEP 8 style guide
- Use type hints where appropriate
- Write docstrings for functions and classes
- Keep functions focused and small

### GUI Code
- Follow PyQt5 best practices
- Use consistent naming conventions
- Maintain the cyberpunk theme
- Ensure accessibility

### Example
```python
def scan_target(target: str, scan_type: str) -> dict:
    """
    Perform a network scan on the specified target.
    
    Args:
        target: IP address or hostname to scan
        scan_type: Type of scan to perform
        
    Returns:
        Dictionary containing scan results
        
    Raises:
        ValueError: If target is invalid
    """
    if not is_valid_target(target):
        raise ValueError(f"Invalid target: {target}")
    
    # Implementation here
    return results
```

## 🧪 Testing

### Running Tests
```bash
# Run all tests
python3 -m pytest

# Run with coverage
python3 -m pytest --cov=core --cov=gui

# Run specific test file
python3 -m pytest tests/test_nmap_scanner.py
```

### Writing Tests
- Test both success and failure cases
- Mock external dependencies
- Use descriptive test names
- Follow AAA pattern (Arrange, Act, Assert)

## 📚 Documentation

### Code Documentation
- Update docstrings when changing functions
- Add comments for complex logic
- Keep README.md current
- Update API documentation

### User Documentation
- Update usage examples
- Add screenshots for UI changes
- Document new features
- Update installation instructions

## 🔒 Security

### Security Considerations
- Never commit sensitive data
- Follow secure coding practices
- Validate all inputs
- Use parameterized queries
- Sanitize scan results

### Reporting Security Issues
- Use private security advisories
- Provide detailed vulnerability information
- Include proof of concept if possible
- Allow time for fixes before disclosure

## 🚀 Pull Request Process

### Before Submitting
1. Ensure all tests pass
2. Update documentation
3. Test on different platforms
4. Check for security issues
5. Follow the commit message format

### Commit Messages
Use conventional commit format:
```
type(scope): description

[optional body]

[optional footer]
```

Examples:
- `feat(nmap): add custom scan options`
- `fix(gui): resolve memory leak in history page`
- `docs(readme): update installation instructions`

### PR Description
- Describe the changes clearly
- Link related issues
- Include screenshots for UI changes
- Mention breaking changes
- List testing performed

## 🏷️ Issue Labels

- `bug`: Something isn't working
- `enhancement`: New feature or request
- `documentation`: Improvements to docs
- `good first issue`: Good for newcomers
- `help wanted`: Extra attention needed
- `security`: Security-related issues

## 📞 Getting Help

- Check existing issues and discussions
- Join our community discussions
- Ask questions in GitHub Discussions
- Review the documentation

## 🎯 Areas for Contribution

### High Priority
- Additional scanner integrations
- AI engine improvements
- Performance optimizations
- Security enhancements

### Medium Priority
- UI/UX improvements
- Documentation updates
- Test coverage
- Code refactoring

### Low Priority
- Minor bug fixes
- Code style improvements
- Documentation typos

## 📄 License

By contributing to DarkPen, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- Project documentation

Thank you for contributing to DarkPen! 🎯 