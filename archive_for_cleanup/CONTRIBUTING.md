# 🤝 Contributing to DarkPen

Thank you for your interest in contributing to DarkPen! This document provides guidelines and information for contributors.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)
- [Style Guides](#style-guides)
- [Additional Notes](#additional-notes)

## 📜 Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

### Our Standards

- **Respectful Communication**: Use welcoming and inclusive language
- **Ethical Behavior**: Respect different viewpoints and experiences
- **Graceful Handling**: Gracefully accept constructive criticism
- **Focus on Community**: Focus on what is best for the community
- **Empathy**: Show empathy towards other community members

## 🎯 How Can I Contribute?

### Reporting Bugs

- Use the GitHub issue tracker
- Include detailed steps to reproduce
- Provide system information
- Include error messages and logs

### Suggesting Enhancements

- Use the GitHub issue tracker
- Describe the enhancement clearly
- Explain why this enhancement would be useful
- Include mockups if applicable

### Pull Requests

- Fork the repository
- Create a feature branch
- Make your changes
- Add tests if applicable
- Submit a pull request

## 🛠️ Development Setup

### Prerequisites

- Python 3.8 or higher
- Git
- Kali Linux or similar penetration testing distribution

### Getting Started

1. **Fork the repository**
   ```bash
   # Fork on GitHub first, then:
   git clone https://github.com/YOUR_USERNAME/darkpen.git
   cd darkpen
   ```

2. **Set up the development environment**
   ```bash
   # Install system dependencies
   sudo apt-get update
   sudo apt-get install -y python3-pyqt5 nmap nikto metasploit-framework

   # Install Python dependencies
   pip3 install -r requirements.txt
   pip3 install -r requirements-dev.txt
   ```

3. **Create a virtual environment (recommended)**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

4. **Set up pre-commit hooks**
   ```bash
   pre-commit install
   ```

### Running Tests

```bash
# Run all tests
python3 -m pytest tests/

# Run with coverage
python3 -m pytest tests/ --cov=darkpen

# Run specific test file
python3 -m pytest tests/test_nmap_scanner.py
```

### Code Quality

```bash
# Run linting
flake8 darkpen/
black darkpen/
isort darkpen/

# Run type checking
mypy darkpen/
```

## 🔄 Pull Request Process

1. **Update the README.md** with details of changes if applicable
2. **Update the CHANGELOG.md** with a note describing your changes
3. **Update version.json** if you're adding new features
4. **Add tests** for new functionality
5. **Ensure all tests pass** before submitting
6. **Follow the existing code style** and conventions

### Pull Request Guidelines

- **Title**: Use a clear and descriptive title
- **Description**: Explain the changes and why they're needed
- **Tests**: Include tests for new functionality
- **Documentation**: Update documentation if needed
- **Screenshots**: Include screenshots for UI changes

## 🐛 Reporting Bugs

### Before Creating Bug Reports

- Check existing issues to avoid duplicates
- Try to reproduce the issue with the latest version
- Check the documentation for known issues

### How Do I Submit a Good Bug Report?

Use the GitHub issue template and include:

- **Use a clear and descriptive title**
- **Describe the exact steps** to reproduce the problem
- **Provide specific examples** to demonstrate the steps
- **Describe the behavior** you observed after following the steps
- **Explain which behavior** you expected to see instead and why
- **Include details** about your configuration and environment
- **Include the output** of any error messages

### Example Bug Report

```markdown
**Bug Description**
Brief description of the bug

**Steps to Reproduce**
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected Behavior**
What you expected to happen

**Actual Behavior**
What actually happened

**Environment**
- OS: [e.g. Kali Linux 2023.1]
- Python Version: [e.g. 3.9.0]
- DarkPen Version: [e.g. 1.0.0]

**Additional Context**
Add any other context about the problem here
```

## 💡 Suggesting Enhancements

### Before Creating Enhancement Suggestions

- Check existing issues to avoid duplicates
- Check the roadmap for planned features
- Consider if the enhancement aligns with project goals

### How Do I Submit a Good Enhancement Suggestion?

- **Use a clear and descriptive title**
- **Provide a step-by-step description** of the suggested enhancement
- **Provide specific examples** to demonstrate the steps
- **Describe the current behavior** and explain which behavior you expected to see instead
- **Include mockups or screenshots** if applicable

## 📝 Style Guides

### Python Code Style

- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Keep functions small and focused
- Use type hints where appropriate

### Git Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests after the first line

### Example Commit Message

```
Add Nmap vulnerability scan feature

- Implement new scan type for vulnerability detection
- Add AI analysis for vulnerability findings
- Update documentation with new feature details

Fixes #123
```

## 📚 Additional Notes

### Issue and Pull Request Labels

- `bug`: Something isn't working
- `enhancement`: New feature or request
- `documentation`: Improvements or additions to documentation
- `good first issue`: Good for newcomers
- `help wanted`: Extra attention is needed
- `question`: Further information is requested
- `wontfix`: This will not be worked on

### Release Process

1. **Version bump**: Update version numbers in relevant files
2. **Changelog**: Update CHANGELOG.md with release notes
3. **Tag**: Create a git tag for the release
4. **Release**: Create a GitHub release with release notes
5. **Deploy**: Update deployment configurations if needed

## 🆘 Getting Help

If you need help with contributing:

- **GitHub Issues**: Create an issue with the `question` label
- **Documentation**: Check the `docs/` directory
- **Community**: Join discussions in GitHub Discussions

## 🙏 Recognition

Contributors will be recognized in:

- The project README
- Release notes
- Contributor statistics on GitHub

---

**Thank you for contributing to DarkPen! 🛡️**

**Repository**: https://github.com/tatah005/darkpen 