import { useState, useEffect } from "react";
import { predictFast, checkHealth } from "../../api/client";
import { getCachedResult, setCachedResult } from "../../utils/storage";

export function useTabState() {
    const [tabUrl, setTabUrl] = useState("");
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [apiOnline, setApiOnline] = useState(true);

    useEffect(() => {
        checkHealth()
            .then(setApiOnline)
            .catch(() => setApiOnline(false));

        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            const tab = tabs[0];
            if (tab && tab.url) {
                setTabUrl(tab.url);
                analyzeUrl(tab.url);
            }
        });
    }, []);

    async function analyzeUrl(url) {
        if (!url || url.startsWith("chrome://") || url.startsWith("about:")) {
            setResult(null);
            return;
        }
        setLoading(true);
        setError(null);
        try {
            const cached = await getCachedResult(url);
            if (cached) {
                setResult(cached);
            } else {
                const data = await predictFast(url);
                setCachedResult(url, data);
                setResult(data);
            }
        } catch (e) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    }

    return { tabUrl, result, loading, error, apiOnline, analyzeUrl };
}