#!/bin/bash

# DarkPen GitHub Upload Script
# This script helps you upload DarkPen to GitHub

echo "🎯 DarkPen GitHub Upload Script"
echo "================================"

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed. Please install git first."
    exit 1
fi

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "❌ Not in a git repository. Please run this script from the DarkPen directory."
    exit 1
fi

echo "✅ Git repository found"

# Check if remote is already configured
if git remote -v | grep -q "origin"; then
    echo "⚠️  Remote 'origin' already configured:"
    git remote -v
    echo ""
    read -p "Do you want to change the remote URL? (y/n): " change_remote
    if [[ $change_remote == "y" || $change_remote == "Y" ]]; then
        read -p "Enter new GitHub repository URL: " new_url
        git remote set-url origin "$new_url"
        echo "✅ Remote URL updated"
    fi
else
    echo "📝 Setting up GitHub remote..."
    read -p "Enter your GitHub repository URL (e.g., https://github.com/username/darkpen.git): " repo_url
    git remote add origin "$repo_url"
    echo "✅ Remote 'origin' added"
fi

# Check current branch
current_branch=$(git branch --show-current)
echo "📍 Current branch: $current_branch"

# Push to GitHub
echo ""
echo "🚀 Pushing to GitHub..."
echo "This will upload all files to your GitHub repository."

read -p "Continue? (y/n): " continue_push
if [[ $continue_push == "y" || $continue_push == "Y" ]]; then
    echo "📤 Pushing to GitHub..."
    
    # Push the main branch
    if git push -u origin main; then
        echo "✅ Successfully pushed to GitHub!"
        echo ""
        echo "🎉 Your DarkPen repository is now live on GitHub!"
        echo ""
        echo "📋 Next steps:"
        echo "1. Visit your GitHub repository"
        echo "2. Enable GitHub Issues (if not already enabled)"
        echo "3. Set up branch protection rules"
        echo "4. Configure GitHub Actions (CI/CD)"
        echo "5. Add a repository description and topics"
        echo "6. Create your first release"
        echo ""
        echo "🔗 Repository URL: $(git remote get-url origin)"
    else
        echo "❌ Failed to push to GitHub. Please check your credentials and try again."
        echo ""
        echo "💡 Troubleshooting tips:"
        echo "- Make sure you have access to the repository"
        echo "- Check your GitHub credentials"
        echo "- Try using a personal access token if needed"
        exit 1
    fi
else
    echo "❌ Upload cancelled"
    exit 0
fi

echo ""
echo "🎯 DarkPen is ready for the world!"
echo "Thank you for contributing to the cybersecurity community! 🛡️" 