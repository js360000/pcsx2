# AI Integration Guide for PCSX2 Enhanced Analysis Framework

## Overview

This guide demonstrates how to integrate AI tools like Claude 4 Sonnet and Google Gemini with PCSX2's enhanced Analysis Framework for real-time source code reconstruction during PlayStation 2 game analysis.

## Supported AI Platforms

### Claude 4 Sonnet (Anthropic)
- **Best for**: Code analysis, function naming, and detailed technical documentation
- **Strengths**: Understanding complex code patterns, generating descriptive function names
- **Use cases**: Function purpose analysis, code structure understanding

### Google Gemini
- **Best for**: Multimodal analysis (video + code), real-time pattern recognition
- **Strengths**: Video analysis, cross-modal correlation, real-time processing
- **Use cases**: Video gameplay analysis, visual-memory correlation

### OpenAI GPT-4/GPT-4V
- **Best for**: General analysis and code understanding
- **Strengths**: Broad knowledge base, code pattern recognition
- **Use cases**: General purpose analysis, documentation generation

## Integration Architecture

```
PCSX2 Game → Analysis Framework → MCP Server → AI Client → AI Service
                     ↓                           ↑
              Video Capture ← Screen Recording ←┘
```

## Setup Instructions

### 1. Basic AI Client Setup

```python
import asyncio
import json
from typing import Dict, Any, Optional

class AIAnalysisClient:
    def __init__(self, ai_service: str, api_key: str):
        self.ai_service = ai_service
        self.api_key = api_key
        self.pcsx2_client = EnhancedPCSX2Client()
    
    async def analyze_function_with_ai(self, function_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze function using AI service"""
        # Generate prompt from PCSX2 data
        prompt_response = self.pcsx2_client.generate_ai_prompt(function_data)
        
        if self.ai_service == "claude":
            return await self.analyze_with_claude(prompt_response["ai_prompt"])
        elif self.ai_service == "gemini":
            return await self.analyze_with_gemini(prompt_response["ai_prompt"])
        
    async def analyze_with_claude(self, prompt: str) -> Dict[str, Any]:
        """Analyze using Claude API"""
        # Implementation for Claude API
        pass
    
    async def analyze_with_gemini(self, prompt: str) -> Dict[str, Any]:
        """Analyze using Gemini API"""
        # Implementation for Gemini API
        pass
```

### 2. Claude Integration Example

```python
import anthropic

class ClaudeAnalyzer:
    def __init__(self, api_key: str):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.pcsx2 = EnhancedPCSX2Client()
    
    async def analyze_ps2_function(self, function_address: int, context: str = ""):
        """Analyze PS2 function using Claude"""
        
        # Get function data from PCSX2
        functions = self.pcsx2.get_discovered_functions()
        
        # Find target function
        target_function = None
        # In real implementation, filter functions by address
        
        if not target_function:
            return {"error": "Function not found"}
        
        # Generate analysis prompt
        prompt = f"""
        Analyze this PlayStation 2 game function:
        
        Address: 0x{function_address:08X}
        Size: {target_function.get('size', 'unknown')} bytes
        Execution Count: {target_function.get('execution_count', 0)}
        Context: {context}
        
        Memory Access Patterns:
        - Graphics registers: {target_function.get('graphics_access', False)}
        - Audio registers: {target_function.get('audio_access', False)}
        - Input registers: {target_function.get('input_access', False)}
        
        Based on this information, please provide:
        1. A descriptive function name (snake_case)
        2. The likely purpose of this function
        3. Whether it's related to graphics, audio, input, or game logic
        4. Confidence level (0.0-1.0)
        
        Format your response as JSON:
        {{
            "suggested_name": "function_name",
            "purpose": "description of function purpose",
            "category": "graphics|audio|input|game_logic|system",
            "confidence": 0.0-1.0,
            "reasoning": "explanation of analysis"
        }}
        """
        
        try:
            response = self.client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Parse Claude's response
            ai_analysis = json.loads(response.content[0].text)
            
            # Send results back to PCSX2
            self.pcsx2.process_ai_response(
                json.dumps(ai_analysis), 
                function_address
            )
            
            return ai_analysis
            
        except Exception as e:
            return {"error": f"Claude analysis failed: {e}"}
```

### 3. Gemini Multimodal Integration

```python
import google.generativeai as genai
import cv2
import base64

class GeminiMultimodalAnalyzer:
    def __init__(self, api_key: str):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-pro-vision')
        self.pcsx2 = EnhancedPCSX2Client()
        self.video_capture = None
    
    def setup_video_capture(self, source: int = 0):
        """Setup video capture for real-time analysis"""
        self.video_capture = cv2.VideoCapture(source)
    
    async def analyze_gameplay_with_video(self, duration: int = 30):
        """Analyze gameplay using video + memory correlation"""
        
        if not self.video_capture:
            return {"error": "Video capture not initialized"}
        
        # Start PCSX2 real-time analysis
        self.pcsx2.start_realtime_analysis()
        
        analysis_results = []
        
        for i in range(duration):
            # Capture video frame
            ret, frame = self.video_capture.read()
            if not ret:
                continue
            
            # Resize and encode frame
            frame = cv2.resize(frame, (640, 480))
            _, buffer = cv2.imencode('.jpg', frame)
            frame_base64 = base64.b64encode(buffer).decode('utf-8')
            
            # Get current memory state from PCSX2
            memory_state = self.pcsx2.get_game_state()
            active_functions = self.pcsx2.get_discovered_functions()
            
            # Analyze with Gemini
            prompt = f"""
            Analyze this PlayStation 2 game screenshot and correlate it with the memory state:
            
            Memory State: {memory_state}
            Active Functions: {len(active_functions.get('functions', []))} functions detected
            
            What is happening in the game? Describe:
            1. Game state (menu, gameplay, loading, etc.)
            2. Player actions visible
            3. UI elements present
            4. Likely memory operations occurring
            
            Format as JSON:
            {{
                "game_state": "description",
                "player_action": "description", 
                "ui_elements": ["list", "of", "elements"],
                "memory_operations": ["list", "of", "likely", "operations"],
                "suggested_context": "context_name"
            }}
            """
            
            try:
                # Convert frame to PIL Image
                from PIL import Image
                import io
                
                image_data = base64.b64decode(frame_base64)
                image = Image.open(io.BytesIO(image_data))
                
                # Analyze with Gemini
                response = self.model.generate_content([prompt, image])
                video_analysis = json.loads(response.text)
                
                # Update PCSX2 context based on analysis
                if 'suggested_context' in video_analysis:
                    self.pcsx2.set_gameplay_context(video_analysis['suggested_context'])
                
                # Add video analysis to PCSX2
                self.pcsx2.add_video_frame_analysis(json.dumps(video_analysis))
                
                analysis_results.append({
                    "timestamp": i,
                    "video_analysis": video_analysis,
                    "memory_state": memory_state
                })
                
            except Exception as e:
                print(f"Gemini analysis failed: {e}")
            
            time.sleep(1)  # Process one frame per second
        
        # Stop PCSX2 analysis
        self.pcsx2.stop_realtime_analysis()
        
        return {
            "total_frames": len(analysis_results),
            "analysis_results": analysis_results,
            "summary": await self.generate_analysis_summary(analysis_results)
        }
    
    async def generate_analysis_summary(self, results: list) -> dict:
        """Generate summary of video-memory correlation analysis"""
        
        summary_prompt = f"""
        Analyze this sequence of {len(results)} video-memory correlation results:
        
        {json.dumps(results, indent=2)}
        
        Generate a comprehensive summary:
        1. Main gameplay activities observed
        2. Memory usage patterns
        3. Suggested function categories
        4. Recommendations for reverse engineering focus
        
        Format as JSON:
        {{
            "main_activities": ["list"],
            "memory_patterns": ["list"],
            "function_categories": ["list"],
            "re_recommendations": ["list"]
        }}
        """
        
        try:
            response = self.model.generate_content(summary_prompt)
            return json.loads(response.text)
        except Exception as e:
            return {"error": f"Summary generation failed: {e}"}
```

### 4. Continuous AI-Assisted Analysis

```python
class ContinuousAIAnalyzer:
    def __init__(self, claude_key: str, gemini_key: str):
        self.claude = ClaudeAnalyzer(claude_key)
        self.gemini = GeminiMultimodalAnalyzer(gemini_key)
        self.pcsx2 = EnhancedPCSX2Client()
        self.analysis_queue = asyncio.Queue()
        self.running = False
    
    async def start_continuous_analysis(self):
        """Start continuous AI-assisted analysis"""
        self.running = True
        
        # Start PCSX2 monitoring
        self.pcsx2.start_realtime_analysis()
        self.gemini.setup_video_capture()
        
        # Start analysis tasks
        tasks = [
            asyncio.create_task(self.function_analysis_loop()),
            asyncio.create_task(self.video_analysis_loop()),
            asyncio.create_task(self.correlation_analysis_loop())
        ]
        
        await asyncio.gather(*tasks)
    
    async def function_analysis_loop(self):
        """Continuously analyze discovered functions with Claude"""
        while self.running:
            try:
                # Get new functions from PCSX2
                functions_response = self.pcsx2.get_discovered_functions()
                
                # Analyze each function with Claude
                for function in functions_response.get('functions', []):
                    analysis = await self.claude.analyze_ps2_function(
                        function['address'], 
                        function.get('context', '')
                    )
                    
                    # Queue for correlation analysis
                    await self.analysis_queue.put({
                        'type': 'function',
                        'data': analysis,
                        'function': function
                    })
                
                await asyncio.sleep(5)  # Analyze every 5 seconds
                
            except Exception as e:
                print(f"Function analysis error: {e}")
                await asyncio.sleep(1)
    
    async def video_analysis_loop(self):
        """Continuously analyze video with Gemini"""
        while self.running:
            try:
                # Analyze 10 seconds of gameplay
                video_analysis = await self.gemini.analyze_gameplay_with_video(10)
                
                # Queue for correlation
                await self.analysis_queue.put({
                    'type': 'video',
                    'data': video_analysis
                })
                
            except Exception as e:
                print(f"Video analysis error: {e}")
                await asyncio.sleep(1)
    
    async def correlation_analysis_loop(self):
        """Correlate function and video analysis"""
        function_analyses = []
        video_analyses = []
        
        while self.running:
            try:
                # Process analysis queue
                while not self.analysis_queue.empty():
                    item = await self.analysis_queue.get()
                    
                    if item['type'] == 'function':
                        function_analyses.append(item)
                    elif item['type'] == 'video':
                        video_analyses.append(item)
                
                # Correlate recent analyses
                if function_analyses and video_analyses:
                    correlation = await self.correlate_analyses(
                        function_analyses[-5:],  # Last 5 function analyses
                        video_analyses[-1:]      # Last video analysis
                    )
                    
                    # Send correlation back to PCSX2
                    self.pcsx2.correlate_video_with_memory(
                        json.dumps(correlation),
                        "ai_correlation"
                    )
                
                await asyncio.sleep(2)
                
            except Exception as e:
                print(f"Correlation analysis error: {e}")
                await asyncio.sleep(1)
    
    async def correlate_analyses(self, function_analyses: list, video_analyses: list) -> dict:
        """Correlate function and video analyses"""
        
        correlation_prompt = f"""
        Correlate these function analyses with video analyses:
        
        Function Analyses:
        {json.dumps(function_analyses, indent=2)}
        
        Video Analyses:
        {json.dumps(video_analyses, indent=2)}
        
        Generate correlation insights:
        1. Which functions are likely active during observed gameplay?
        2. How do video events correlate with function execution?
        3. What can we infer about game architecture?
        
        Format as JSON:
        {{
            "active_functions": ["list"],
            "correlations": ["list"],
            "architecture_insights": ["list"]
        }}
        """
        
        try:
            # Use Claude for correlation analysis
            response = self.claude.client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=1000,
                messages=[{"role": "user", "content": correlation_prompt}]
            )
            
            return json.loads(response.content[0].text)
            
        except Exception as e:
            return {"error": f"Correlation failed: {e}"}
    
    def stop_analysis(self):
        """Stop continuous analysis"""
        self.running = False
        self.pcsx2.stop_realtime_analysis()
```

## Usage Examples

### Basic Function Analysis with Claude

```python
# Setup
claude_analyzer = ClaudeAnalyzer("your-claude-api-key")

# Analyze a specific function
result = await claude_analyzer.analyze_ps2_function(0x00100000, "main_gameplay")
print(f"Function analysis: {result}")
```

### Multimodal Analysis with Gemini

```python
# Setup
gemini_analyzer = GeminiMultimodalAnalyzer("your-gemini-api-key")

# Analyze 60 seconds of gameplay with video correlation
result = await gemini_analyzer.analyze_gameplay_with_video(60)
print(f"Multimodal analysis complete: {result['total_frames']} frames analyzed")
```

### Continuous AI Analysis

```python
# Setup
continuous_analyzer = ContinuousAIAnalyzer(
    claude_key="your-claude-key",
    gemini_key="your-gemini-key"
)

# Start continuous analysis
await continuous_analyzer.start_continuous_analysis()
```

## Best Practices

### 1. API Rate Limiting
- Implement proper rate limiting for AI API calls
- Queue requests during high-activity periods
- Use caching for similar analysis requests

### 2. Cost Management
- Monitor API usage and costs
- Use lower-cost models for initial screening
- Reserve high-end models for detailed analysis

### 3. Error Handling
- Implement robust error handling for API failures
- Provide fallback analysis methods
- Log all API interactions for debugging

### 4. Privacy and Security
- Never send sensitive data to AI services
- Implement data anonymization where needed
- Follow AI service privacy guidelines

## Integration Workflow

1. **Game Start**: Initialize AI clients and PCSX2 connection
2. **Real-time Analysis**: Continuously monitor game execution
3. **Function Discovery**: Use Claude for function naming and analysis
4. **Video Correlation**: Use Gemini for visual-memory correlation
5. **Pattern Recognition**: Combine AI insights for comprehensive analysis
6. **Export Results**: Generate reports and scripts for external tools

## Troubleshooting

### Common Issues

1. **API Connection Failures**
   - Check API keys and network connectivity
   - Implement retry logic with exponential backoff

2. **Video Capture Issues**
   - Ensure OpenCV is properly installed
   - Check video source permissions and availability

3. **Memory/Performance Issues**
   - Limit queue sizes for analysis data
   - Implement periodic cleanup of old data

4. **Analysis Quality Issues**
   - Tune prompts for better AI responses
   - Adjust analysis parameters based on results

### Support

For issues with the AI integration:
1. Check PCSX2 Analysis Framework logs
2. Verify AI service API status
3. Review network connectivity
4. Consult AI service documentation

This integration enables powerful AI-assisted reverse engineering capabilities, combining real-time game analysis with advanced AI models for comprehensive source code reconstruction.