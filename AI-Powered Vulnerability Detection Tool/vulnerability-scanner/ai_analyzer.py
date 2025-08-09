import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import re

class AIAnalyzer:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.load_model()
    
    def load_model(self):
        """Load pre-trained model or train a new one"""
        try:
            self.model = joblib.load('models/vulnerability_model.pkl')
            self.vectorizer = joblib.load('models/vectorizer.pkl')
            print("Loaded pre-trained model")
        except:
            print("No pre-trained model found. Training new model...")
            self.train_model()
    
    def train_model(self):
        """Train a new vulnerability detection model"""
        # Sample training data (in a real scenario, you'd use a large dataset)
        data = {
            'url': [
                'http://example.com/?id=1',
                'http://test.com/?q=<script>alert(1)</script>',
                'http://demo.com/?file=../../../etc/passwd',
                'http://site.com/?redirect=//evil.com',
                'http://app.com/login.php',
                'http://blog.com/post.php?id=1',
                'http://shop.com/product.php?id=1',
                'http://forum.com/thread.php?id=1',
                'http://news.com/article.php?id=1',
                'http://portal.com/home.php'
            ],
            'vulnerable': [1, 1, 1, 1, 0, 0, 0, 0, 0, 0]
        }
        
        df = pd.DataFrame(data)
        
        # Feature engineering
        df['features'] = df['url'].apply(self.extract_features)
        
        # Vectorize features
        self.vectorizer = TfidfVectorizer(max_features=100)
        X = self.vectorizer.fit_transform(df['features'])
        y = df['vulnerable']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        
        # Train model
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Model accuracy: {accuracy:.2f}")
        
        # Save model
        joblib.dump(self.model, 'models/vulnerability_model.pkl')
        joblib.dump(self.vectorizer, 'models/vectorizer.pkl')
    
    def extract_features(self, url):
        """Extract features from URL for ML analysis"""
        features = []
        
        # Length features
        features.append(f"len_{len(url)}")
        
        # Special characters
        special_chars = ['<', '>', '"', "'", '&', '/', '\\', '?', '=', '.', '-', '_']
        for char in special_chars:
            count = url.count(char)
            if count > 0:
                features.append(f"char_{char}_{count}")
        
        # Suspicious patterns
        patterns = [
            (r'select.*from', 'sql_pattern'),
            (r'union.*select', 'sql_union'),
            (r'<script', 'xss_script'),
            (r'javascript:', 'xss_js'),
            (r'\.\.\/', 'dir_traversal'),
            (r'etc\/passwd', 'file_disclosure'),
            (r'redirect=.*http', 'open_redirect'),
            (r'php:\/\/', 'file_inclusion')
        ]
        
        for pattern, name in patterns:
            if re.search(pattern, url, re.IGNORECASE):
                features.append(name)
        
        # Parameter count
        params = url.split('?')[-1].split('&') if '?' in url else []
        features.append(f"params_{len(params)}")
        
        return ' '.join(features)
    
    def analyze(self, url):
        """Analyze a URL for potential vulnerabilities using AI"""
        features = self.extract_features(url)
        vectorized = self.vectorizer.transform([features])
        prediction = self.model.predict(vectorized)[0]
        probability = self.model.predict_proba(vectorized)[0][1]
        
        return {
            'url': url,
            'is_vulnerable': bool(prediction),
            'confidence': float(probability),
            'risk_level': 'high' if probability > 0.8 else 'medium' if probability > 0.5 else 'low'
        }