#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.aws_bedrock_service import AWSBedrockService
import asyncio

async def test_embeddings():
    """Test AWS Titan embeddings functionality."""
    try:
        print("Initializing AWS Bedrock service...")
        bedrock_service = AWSBedrockService()

        print("Testing embeddings...")
        test_texts = ["phishing attack techniques", "credential access methods"]
        embeddings = bedrock_service.get_embeddings(test_texts, "search_query")

        print(f"✓ Successfully generated {len(embeddings)} embeddings")
        print(f"✓ Embedding dimensions: {len(embeddings[0]) if embeddings else 0}")

        return True

    except Exception as e:
        print(f"✗ Error testing embeddings: {e}")
        return False

async def test_text_generation():
    """Test AWS Titan text generation functionality."""
    try:
        print("\nTesting text generation...")
        bedrock_service = AWSBedrockService()

        test_context = """
Technique: Phishing (T1566)
Description: Adversaries may send spearphishing emails with a malicious attachment or link.
Tactics: initial-access
Platforms: Windows, macOS, Linux
Relevance Score: 0.95
"""

        response = await bedrock_service.generate_conversational_response(
            query="What are common phishing techniques?",
            context=test_context,
            max_tokens=200
        )

        print(f"✓ Generated response: {len(response)} characters")
        print(f"✓ Response preview: {response[:100]}...")

        return True

    except Exception as e:
        print(f"✗ Error testing text generation: {e}")
        return False

async def main():
    """Main test function."""
    print("=== AWS Bedrock Service Test ===\n")

    # Test embeddings first
    embeddings_ok = await test_embeddings()

    # Test text generation
    text_gen_ok = await test_text_generation()

    print("\n=== Test Results ===")
    print(f"Embeddings: {'✓ PASS' if embeddings_ok else '✗ FAIL'}")
    print(f"Text Generation: {'✓ PASS' if text_gen_ok else '✗ FAIL'}")

    if embeddings_ok and text_gen_ok:
        print("\n🎉 All tests passed! AWS Bedrock service is working correctly.")
    else:
        print("\n❌ Some tests failed. Check AWS credentials and model availability.")

if __name__ == "__main__":
    asyncio.run(main())
