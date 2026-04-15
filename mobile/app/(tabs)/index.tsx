import { ActivityIndicator, View, Text, TextInput, TouchableOpacity, StyleSheet, ScrollView, Platform } from "react-native";
import { useState } from "react";

const verdictColors: Record<string, string> = {
  Safe: "#22c55e",
  safe: "#22c55e",
  suspicious: "#facc15",
  Suspicious: "#facc15",
  Scam: "#ef4444",
  scam: "#ef4444",
  Phishing: "#ef4444",
  phishing: "#ef4444",
  Error: "#94a3b8",
  error: "#94a3b8",
};

export default function HomeScreen() {
  const [text, setText] = useState("");
  const [inputType, setInputType] = useState<"email" | "url">("email");
  const [result, setResult] = useState<any>(null);
  const [history, setHistory] = useState<Array<any>>([]);
  const [loading, setLoading] = useState(false);

  const determineVerdictColor = (verdict: string, score: number) => {
    if (verdict in verdictColors) {
      return verdictColors[verdict];
    }
    if (score >= 0.7) return "#ef4444";
    if (score >= 0.35) return "#facc15";
    return "#22c55e";
  };

  const getConfidenceLabel = (confidenceRaw: number | string) => {
    if (typeof confidenceRaw === "string") return confidenceRaw;
    if (confidenceRaw >= 0.75) return "High";
    if (confidenceRaw >= 0.4) return "Medium";
    return "Low";
  };

  const getVerdictLabel = (verdict: string) => {
    const normalized = verdict.toLowerCase();
    if (normalized === "error") return "🚫 Error";
    if (normalized.includes("safe") && normalized.includes("suspicious")) return "🟡 Suspicious Content";
    if (normalized.includes("safe")) return "🟢 Safe Content";
    if (normalized.includes("scam") || normalized.includes("phishing") || normalized.includes("malicious")) return "⚠️ High Risk Scam Detected";
    if (normalized.includes("suspicious")) return "🟡 Suspicious Content";
    return `• ${verdict}`;
  };

  const detectAttackType = (attackType: string | undefined, input: string, verdict: string) => {
    if (attackType && attackType.trim() && attackType.toLowerCase() !== "unknown") {
      return attackType;
    }

    const normalized = input.toLowerCase();
    if (normalized.match(/\b(job|recruiter|hiring|interview|career)\b/)) return "Job scam";
    if (normalized.match(/\b(visa|immigration|passport|green card|immigrant|immigration)\b/)) return "Visa/Immigration scam";
    if (normalized.match(/\b(package|delivery|tracking|parcel|shipment|UPS|FedEx|DHL)\b/)) return "Package delivery scam";
    if (normalized.match(/\b(bank|account|payment|transaction|invoice|verify|secure|paypal|stripe)\b/)) return "Banking/payment scam";
    if (normalized.match(/\b(otp|one[- ]time code|verification code|PIN|code)\b/)) return "OTP/code scam";
    if (normalized.match(/\b(tech support|support team|help desk|computer issue|virus|malware|system update)\b/)) return "Tech support scam";
    if (normalized.match(/\b(call transcript|call|voicemail|phone call|phone)\b/)) return "Suspicious call transcript";
    if (normalized.match(/\b(whatsapp|sms|text message|message|whatsApp|sms scam)\b/)) return "WhatsApp/SMS scam";
    if (normalized.match(/\b(phishing|password|login|account suspended|verify your account|security alert)\b/)) return verdict.toLowerCase() === "safe" ? "Phishing email" : "Phishing email";
    if (normalized.match(/https?:\/\//)) return "Suspicious URL";
    return "Unknown";
  };

  const getIndicatorValue = (value: boolean | undefined) => {
    if (!result) return false;
    if (result.verdict === "Safe") return false;
    return !!value;
  };

  const analyzeText = async () => {
    if (!text.trim()) return;

    setLoading(true);
    setResult(null);

    try {
      const backendHost = Platform.OS === "android" ? "10.0.2.2" : "127.0.0.1";
      const response = await fetch(`http://${backendHost}:8000/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          input_text: text,
          input_type: inputType,
        }),
      });

      if (!response.ok) {
        throw new Error(`Backend returned status ${response.status}`);
      }

      const data = await response.json();
      if (!data || typeof data.verdict !== "string") {
        throw new Error("Invalid analysis response from backend.");
      }

      setResult(data);
      setHistory((current) => [
        {
          id: Date.now(),
          text,
          type: inputType,
          verdict: data.verdict,
          score: Math.round((data.score ?? 0) * 100),
          time: new Date().toLocaleString(),
        },
        ...current,
      ]);
    } catch (error) {
      const errorResult = {
        verdict: "Error",
        score: 0,
        explanations: ["Could not connect to backend. Make sure backend is running."],
        indicators: {},
      };
      setResult(errorResult);
      setHistory((current) => [
        {
          id: Date.now(),
          text,
          type: inputType,
          verdict: "Error",
          score: 0,
          time: new Date().toLocaleString(),
        },
        ...current,
      ]);
    }

    setLoading(false);
  };

  const riskPercent = result ? Math.round((result.score ?? 0) * 100) : 0;
  const confidenceRaw = result ? (result.confidence ?? result.score ?? 0) : 0;
  const confidenceLabel = getConfidenceLabel(confidenceRaw);
  const verdictColor = result ? determineVerdictColor(result.verdict, result.score ?? 0) : "#22c55e";
  const attackLabel = result ? detectAttackType(result.attack_type, text, result.verdict ?? "") : "Unknown";

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.tagline}>
        AI-powered scam detection and investigation tool for emails, messages, calls, and job offers.
      </Text>
      <Text style={styles.title}>PhishGuard AI: Scam Analyzer</Text>
      <Text style={styles.subtitle}>
        Analyze phishing emails, suspicious URLs, job scams, fake recruiter messages, visa/immigration scams,
        package delivery scams, banking/payment scams, OTP/code scams, tech support scams,
        suspicious call transcripts, and WhatsApp/SMS scam messages.
      </Text>

      <View style={styles.toggleRow}>
        <TouchableOpacity
          style={[
            styles.toggleButton,
            inputType === "email" ? styles.toggleButtonActive : styles.toggleButtonInactive,
          ]}
          onPress={() => setInputType("email")}
        >
          <Text style={inputType === "email" ? styles.toggleTextActive : styles.toggleTextInactive}>
            Email
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[
            styles.toggleButton,
            inputType === "url" ? styles.toggleButtonActive : styles.toggleButtonInactive,
          ]}
          onPress={() => setInputType("url")}
        >
          <Text style={inputType === "url" ? styles.toggleTextActive : styles.toggleTextInactive}>
            URL
          </Text>
        </TouchableOpacity>
      </View>

      <TextInput
        style={styles.input}
        placeholder={
          inputType === "email"
            ? "Paste suspicious email content here..."
            : "Paste suspicious URL here..."
        }
        multiline
        value={text}
        onChangeText={setText}
      />

      <TouchableOpacity style={styles.button} onPress={analyzeText}>
        {loading ? (
          <View style={styles.loaderContent}>
            <ActivityIndicator size="small" color="#ffffff" style={styles.loader} />
            <Text style={styles.buttonText}>Analyzing threat patterns...</Text>
          </View>
        ) : (
          <Text style={styles.buttonText}>Analyze</Text>
        )}
      </TouchableOpacity>

      {result && (
        <View style={styles.resultCard}>
          <Text style={[styles.resultTitle, { color: verdictColor }]}>{getVerdictLabel(result.verdict)}</Text>
          <Text style={styles.score}>Risk Score: {riskPercent}%</Text>

          <View style={styles.riskBarBackground}>
            <View style={[styles.riskBarFill, { width: `${riskPercent}%`, backgroundColor: verdictColor }]} />
          </View>

          <Text style={styles.confidence}>Confidence: {confidenceLabel}</Text>
          <Text style={styles.attackType}>Attack type: {attackLabel}</Text>

          <Text style={styles.sectionTitle}>Why it matters</Text>
          <Text style={styles.bullet}>• Phishing and malicious links can steal your credentials and personal data.</Text>
          <Text style={styles.bullet}>• Detecting email scams early helps prevent account takeover.</Text>
          <Text style={styles.bullet}>• A suspicious link can lead to fraud, malware, or identity theft.</Text>

          <Text style={styles.sectionTitle}>What we found</Text>
          {result.explanations?.map((item: string, index: number) => (
            <Text key={index} style={styles.indicator}>• {item}</Text>
          ))}

          <Text style={styles.sectionTitle}>Recommended action</Text>
          <Text style={styles.recommended}>• {result.recommended_action ?? "Keep the content blocked and review it carefully before taking any action."}</Text>

          <Text style={styles.sectionTitle}>Indicators</Text>
          <Text style={styles.indicator}>Urgent words: {getIndicatorValue(result.indicators?.urgent_words) ? "Yes" : "No"}</Text>
          <Text style={styles.indicator}>Shortened URL: {getIndicatorValue(result.indicators?.shortened_url) ? "Yes" : "No"}</Text>
          <Text style={styles.indicator}>IP URL: {getIndicatorValue(result.indicators?.ip_url) ? "Yes" : "No"}</Text>
          <Text style={styles.indicator}>Suspicious keywords: {getIndicatorValue(result.indicators?.suspicious_keywords_count > 0) ? result.indicators?.suspicious_keywords_count ?? 0 : 0}</Text>
        </View>
      )}

      {history.length > 0 && (
        <View style={styles.historyCard}>
          <Text style={styles.sectionTitle}>Scan History</Text>
          {history.slice(0, 5).map((entry) => (
            <View key={entry.id} style={styles.historyRow}>
              <View style={styles.historyMeta}>
                <Text style={styles.historyText}>{entry.type.toUpperCase()}</Text>
                <Text style={styles.historyTime}>{entry.time}</Text>
              </View>
              <Text style={[styles.historyVerdict, { color: determineVerdictColor(entry.verdict, entry.score / 100) }]}>
                {entry.verdict}
              </Text>
              <Text style={styles.historyScore}>{entry.score}%</Text>
            </View>
          ))}
        </View>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    backgroundColor: "#0f172a",
    padding: 20,
    justifyContent: "center",
  },
  title: {
    color: "white",
    fontSize: 28,
    fontWeight: "700",
    marginBottom: 12,
    textAlign: "center",
  },
  tagline: {
    color: "#94a3b8",
    fontSize: 14,
    lineHeight: 20,
    textAlign: "center",
    marginHorizontal: 4,
    marginBottom: 10,
  },
  subtitle: {
    color: "#cbd5e1",
    fontSize: 15,
    lineHeight: 22,
    textAlign: "center",
    marginHorizontal: 4,
    marginBottom: 18,
  },
  toggleRow: {
    flexDirection: "row",
    gap: 12,
    marginBottom: 15,
    justifyContent: "center",
  },
  toggleButton: {
    flex: 1,
    paddingVertical: 12,
    borderRadius: 12,
    alignItems: "center",
  },
  toggleButtonActive: {
    backgroundColor: "#2563eb",
  },
  toggleButtonInactive: {
    backgroundColor: "#1e293b",
  },
  toggleTextActive: {
    color: "white",
    fontWeight: "700",
  },
  toggleTextInactive: {
    color: "#94a3b8",
    fontWeight: "700",
  },
  input: {
    backgroundColor: "white",
    borderRadius: 10,
    padding: 12,
    minHeight: 140,
    marginBottom: 15,
    textAlignVertical: "top",
  },
  button: {
    backgroundColor: "#22c55e",
    padding: 15,
    borderRadius: 10,
    alignItems: "center",
    marginBottom: 20,
  },
  buttonText: {
    color: "white",
    fontWeight: "700",
    fontSize: 16,
  },
  resultCard: {
    backgroundColor: "#1e293b",
    borderRadius: 12,
    padding: 16,
  },
  resultTitle: {
    color: "white",
    fontSize: 22,
    fontWeight: "700",
    marginBottom: 8,
  },
  score: {
    color: "#93c5fd",
    fontSize: 16,
    marginBottom: 12,
  },
  riskBarBackground: {
    width: "100%",
    height: 12,
    borderRadius: 8,
    backgroundColor: "#0f172a",
    overflow: "hidden",
    marginBottom: 16,
  },
  riskBarFill: {
    height: "100%",
    borderRadius: 8,
  },
  sectionTitle: {
    color: "white",
    fontSize: 17,
    fontWeight: "700",
    marginTop: 8,
    marginBottom: 8,
  },
  bullet: {
    color: "#e2e8f0",
    fontSize: 15,
    marginBottom: 6,
  },
  indicator: {
    color: "#cbd5e1",
    fontSize: 14,
    marginBottom: 4,
  },
  historyCard: {
    backgroundColor: "#1e293b",
    borderRadius: 12,
    padding: 16,
  },
  historyRow: {
    borderTopWidth: 1,
    borderTopColor: "#334155",
    paddingTop: 12,
    marginTop: 12,
  },
  historyMeta: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: 6,
  },
  historyText: {
    color: "#cbd5e1",
    fontSize: 13,
    fontWeight: "700",
  },
  historyTime: {
    color: "#94a3b8",
    fontSize: 12,
  },
  historyVerdict: {
    fontSize: 15,
    fontWeight: "700",
  },
  historyScore: {
    color: "#cbd5e1",
    fontSize: 14,
    marginTop: 4,
  },
  confidence: {
    color: "#a5b4fc",
    fontSize: 14,
    marginBottom: 8,
    fontWeight: "700",
  },
  loaderContent: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 8,
  },
  loader: {
    marginRight: 8,
  },
  attackType: {
    color: "#f8fafc",
    fontSize: 15,
    marginBottom: 10,
    fontWeight: "700",
  },
  recommended: {
    color: "#e2e8f0",
    fontSize: 14,
    lineHeight: 20,
    marginBottom: 8,
  },
});