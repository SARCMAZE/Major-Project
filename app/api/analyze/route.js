import { GoogleGenerativeAI } from "@google/generative-ai";
import fs from 'fs';
import path from 'path';

export async function POST(request) {
  try {
    // Read dataset from file
    const filePath = path.join(process.cwd(), 'data', 'dataset.jsonl');
    const fileContent = fs.readFileSync(filePath, 'utf8');
    const lines = fileContent.trim().split('\n').filter(line => line.trim() !== "");
    const allAlerts = lines.map(line => JSON.parse(line));

    // CHUNKING LOGIC: Send only a small chunk to the LLM for now
    // CHANGE THIS LATER: Increase chunk size or remove slice when using a more powerful API model/higher rate limits
    const chunkToProcess = allAlerts.slice(0, 2);

    // Hardcoded mock Threat Intel
    const threatIntel = {
      abuse: 89,
      domain: "known-botnet-node.com"
    };

    // Minimize payload to save tokens
    const minimizedAlerts = chunkToProcess.map(alert => ({
      id: alert["flow id"],
      src_ip: alert["source ip"],
      dst_ip: alert["destination ip"],
      event: alert["label"],
      triage_score: alert["l1_score"],
      reason: alert["status"]
    }));

    let llmJson = [];

    try {
      if (!process.env.GEMINI_API_KEY) {
        throw new Error("API_KEY_INVALID - No key found in environment");
      }

      // Connect to Google Generative AI
      const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
      const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

      // Ultra-Short LLM Prompt
      const prompt = `SOC L2 task. Analyze network alerts & threat intel. Output ONLY valid JSON: An array of objects, exactly matching the length of input alerts, each with {"id": "flow id from input", "score":int, "cat":"string", "ctx":"string", "remedy":["string"]}. No conversational text. Input Alerts: ${JSON.stringify(minimizedAlerts)}, Intel: ${JSON.stringify(threatIntel)}`;

      const result = await model.generateContent(prompt);
      const response = await result.response;
      let text = response.text();

      if (text.startsWith("```json")) {
        text = text.replace(/^```json\n/, "").replace(/\n```$/, "");
      } else if (text.startsWith("```")) {
        text = text.replace(/^```\n/, "").replace(/\n```$/, "");
      }

      llmJson = JSON.parse(text);

    } catch (apiError) {
      console.warn("Falling back to Mock Analysis because of API Error:", apiError.message);

      // FALLBACK LOGIC: If the API key is missing or invalid, use mock data so the dashboard still works!
      llmJson = chunkToProcess.map(alert => {
        // Generate a random score between 60 and 95
        const mockScore = Math.floor(Math.random() * 35) + 60;
        return {
          id: alert["flow id"],
          score: mockScore,
          cat: mockScore > 80 ? "Critical Network Threat" : "Suspicious Activity",
          ctx: "[MOCK DATA - NO API KEY] This alert shows an anomalous flow duration with large byte transfers matching known botnet signatures.",
          remedy: [
            "Block IP " + alert["destination ip"] + " at the edge firewall.",
            "Isolate " + alert["source ip"] + " for endpoint forensics.",
            "Update IPS rules for matching packet sizes."
          ]
        };
      });
    }

    // Map LLM responses back to the original alerts
    const finalResponse = chunkToProcess.map(alert => {
      const analysis = llmJson.find(a => a.id === alert["flow id"]) || {
        score: 0,
        cat: "Unknown",
        ctx: "Failed to parse analysis for this alert.",
        remedy: ["Manual review required."]
      };

      return {
        original_alert: alert,
        analysis: analysis,
        threat_intel: threatIntel
      };
    });

    return new Response(JSON.stringify(finalResponse), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error("Error processing alert:", error);
    return new Response(JSON.stringify({ error: "Failed to process alert", details: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
