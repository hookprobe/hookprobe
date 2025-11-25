"""
AI Content Generation Service
Integrates with OpenAI and Anthropic for AI-powered content creation.
"""

import os
import json
import requests
from typing import Dict, List, Optional
from django.conf import settings


class AIContentService:
    """
    Service for generating AI-powered content using OpenAI or Anthropic.
    """

    def __init__(self, provider='anthropic'):
        """
        Initialize the AI service.

        Args:
            provider: 'openai' or 'anthropic'
        """
        self.provider = provider.lower()

        if self.provider == 'openai':
            self.api_key = getattr(settings, 'OPENAI_API_KEY', os.getenv('OPENAI_API_KEY'))
            self.model = getattr(settings, 'OPENAI_MODEL', 'gpt-4')
            self.api_url = 'https://api.openai.com/v1/chat/completions'
        elif self.provider == 'anthropic':
            self.api_key = getattr(settings, 'ANTHROPIC_API_KEY', os.getenv('ANTHROPIC_API_KEY'))
            self.model = getattr(settings, 'ANTHROPIC_MODEL', 'claude-3-sonnet-20240229')
            self.api_url = 'https://api.anthropic.com/v1/messages'
        else:
            raise ValueError(f"Unknown provider: {provider}")

        if not self.api_key:
            raise ValueError(f"No API key configured for {provider}")

    def generate_blog_post(
        self,
        topic: str,
        keywords: Optional[List[str]] = None,
        research_sources: Optional[List[str]] = None,
        target_length: int = 800
    ) -> Dict:
        """
        Generate a complete blog post.

        Args:
            topic: Main topic of the blog post
            keywords: List of keywords to include
            research_sources: List of source URLs used for research
            target_length: Target word count

        Returns:
            Dictionary with title, content, summary, seo_title, seo_description, confidence_score
        """
        # Build the prompt
        prompt = self._build_blog_post_prompt(topic, keywords, research_sources, target_length)

        # Generate content
        response = self._call_api(prompt)

        # Parse response
        return self._parse_blog_post_response(response)

    def generate_title(self, topic: str, keywords: Optional[List[str]] = None) -> str:
        """
        Generate an engaging blog post title.

        Args:
            topic: Main topic
            keywords: Optional keywords

        Returns:
            Generated title
        """
        keywords_str = ', '.join(keywords) if keywords else ''
        prompt = f"""Generate an engaging, SEO-optimized blog post title for the following topic:

Topic: {topic}
Keywords: {keywords_str}

Requirements:
- Attention-grabbing and click-worthy
- Include primary keyword if possible
- 50-60 characters
- Professional tone for cybersecurity audience

Return only the title, no explanation."""

        response = self._call_api(prompt)
        return response.strip()

    def optimize_seo(self, title: str, content: str) -> Dict:
        """
        Generate SEO metadata for a blog post.

        Args:
            title: Post title
            content: Post content

        Returns:
            Dictionary with seo_title, seo_description, seo_keywords, seo_score
        """
        # Truncate content for API call
        content_preview = content[:1000]

        prompt = f"""Generate SEO metadata for this blog post:

Title: {title}
Content (preview): {content_preview}

Provide:
1. SEO Title (50-60 characters, keyword-optimized)
2. Meta Description (150-160 characters, compelling)
3. Keywords (5-10 relevant SEO keywords, comma-separated)
4. SEO Score (0-100, estimate based on optimization)

Return as JSON:
{{
    "seo_title": "...",
    "seo_description": "...",
    "seo_keywords": "...",
    "seo_score": 85
}}"""

        response = self._call_api(prompt)

        try:
            # Try to parse as JSON
            return json.loads(response)
        except json.JSONDecodeError:
            # Fallback to defaults
            return {
                'seo_title': title[:60],
                'seo_description': content_preview[:160],
                'seo_keywords': '',
                'seo_score': 50
            }

    def summarize_text(self, text: str, max_length: int = 300) -> str:
        """
        Generate a summary of the given text.

        Args:
            text: Text to summarize
            max_length: Maximum length of summary

        Returns:
            Summary text
        """
        prompt = f"""Summarize the following text in {max_length} characters or less:

{text}

Provide a concise, engaging summary that captures the main points."""

        response = self._call_api(prompt)
        return response.strip()

    def research_topic(
        self,
        topic: str,
        include_cve: bool = False,
        include_news: bool = True
    ) -> Dict:
        """
        Generate research insights for a topic.

        Args:
            topic: Research topic
            include_cve: Include CVE database information
            include_news: Include recent news

        Returns:
            Dictionary with research summary and key points
        """
        prompt = f"""Research the following cybersecurity topic and provide key insights:

Topic: {topic}
Include CVE information: {include_cve}
Include recent news: {include_news}

Provide:
1. Overview (2-3 sentences)
2. Key Points (5-7 bullet points)
3. Recommended sources to investigate
4. Potential blog post angles

Return as JSON:
{{
    "overview": "...",
    "key_points": ["...", "..."],
    "recommended_sources": ["...", "..."],
    "blog_angles": ["...", "..."]
}}"""

        response = self._call_api(prompt)

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return {
                'overview': response[:300],
                'key_points': [],
                'recommended_sources': [],
                'blog_angles': []
            }

    def _build_blog_post_prompt(
        self,
        topic: str,
        keywords: Optional[List[str]],
        research_sources: Optional[List[str]],
        target_length: int
    ) -> str:
        """Build the prompt for blog post generation."""
        keywords_str = ', '.join(keywords) if keywords else 'none specified'
        sources_str = '\n'.join(f"- {s}" for s in research_sources) if research_sources else 'none provided'

        return f"""Write a comprehensive, professional blog post for a cybersecurity audience.

Topic: {topic}
Target Length: {target_length} words
Keywords to include: {keywords_str}
Research sources:
{sources_str}

Requirements:
- Professional, technical tone appropriate for security professionals
- Use markdown formatting (headers, lists, code blocks where appropriate)
- Include practical examples or use cases
- Mention HookProbe where relevant (it's an open-source security platform)
- SEO-optimized with keyword integration
- Engaging introduction and strong conclusion

Return as JSON:
{{
    "title": "Blog post title",
    "content": "Full markdown content...",
    "summary": "2-3 sentence summary",
    "confidence_score": 0.95
}}"""

    def _parse_blog_post_response(self, response: str) -> Dict:
        """Parse the API response for blog post generation."""
        try:
            # Try to parse as JSON
            data = json.loads(response)
            return {
                'title': data.get('title', 'Untitled'),
                'content': data.get('content', ''),
                'summary': data.get('summary', ''),
                'confidence_score': data.get('confidence_score', 0.7)
            }
        except json.JSONDecodeError:
            # Fallback: treat entire response as content
            return {
                'title': 'AI Generated Post',
                'content': response,
                'summary': response[:300],
                'confidence_score': 0.6
            }

    def _call_api(self, prompt: str) -> str:
        """
        Call the AI API (OpenAI or Anthropic).

        Args:
            prompt: The prompt to send

        Returns:
            Generated text response
        """
        if self.provider == 'openai':
            return self._call_openai(prompt)
        elif self.provider == 'anthropic':
            return self._call_anthropic(prompt)
        else:
            raise ValueError(f"Unknown provider: {self.provider}")

    def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API."""
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

        data = {
            'model': self.model,
            'messages': [
                {'role': 'system', 'content': 'You are a professional cybersecurity content writer with expertise in network security, threat detection, and security operations.'},
                {'role': 'user', 'content': prompt}
            ],
            'temperature': 0.7,
            'max_tokens': 4000
        }

        response = requests.post(self.api_url, headers=headers, json=data, timeout=60)
        response.raise_for_status()

        result = response.json()
        return result['choices'][0]['message']['content']

    def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic API."""
        headers = {
            'x-api-key': self.api_key,
            'anthropic-version': '2023-06-01',
            'Content-Type': 'application/json'
        }

        data = {
            'model': self.model,
            'max_tokens': 4000,
            'messages': [
                {
                    'role': 'user',
                    'content': f"You are a professional cybersecurity content writer with expertise in network security, threat detection, and security operations.\n\n{prompt}"
                }
            ]
        }

        response = requests.post(self.api_url, headers=headers, json=data, timeout=60)
        response.raise_for_status()

        result = response.json()
        return result['content'][0]['text']


# Convenience functions
def generate_blog_post(topic: str, provider='anthropic', **kwargs) -> Dict:
    """
    Quick function to generate a blog post.

    Args:
        topic: Blog post topic
        provider: 'openai' or 'anthropic'
        **kwargs: Additional arguments for generate_blog_post()

    Returns:
        Generated blog post data
    """
    service = AIContentService(provider=provider)
    return service.generate_blog_post(topic, **kwargs)


def optimize_seo_metadata(title: str, content: str, provider='anthropic') -> Dict:
    """
    Quick function to generate SEO metadata.

    Args:
        title: Post title
        content: Post content
        provider: 'openai' or 'anthropic'

    Returns:
        SEO metadata
    """
    service = AIContentService(provider=provider)
    return service.optimize_seo(title, content)
