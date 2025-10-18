#!/usr/bin/env python3
"""
UNSW-NB15 Attack Detection - Inference Demo
==========================================

Demonstrates how to load and use the trained attack detection model
for predicting on new network traffic samples.

Usage:
    python3 predict_attacks.py
"""
import joblib
import pandas as pd
import numpy as np

# Model path (adjust if needed)
MODEL_PATH = 'trained_models/unsw_attack_detector.joblib'


def load_model():
    """Load the trained model pipeline."""
    print("Loading trained model...")
    try:
        model = joblib.load(MODEL_PATH)
        print(f"✓ Model loaded from: {MODEL_PATH}")
        return model
    except FileNotFoundError:
        print(f"ERROR: Model not found at {MODEL_PATH}")
        print("Please run train_unsw_nb15.py first to train the model.")
        return None


def predict_sample(model, sample_data):
    """
    Predict attack/benign for a single sample or batch.
    
    Args:
        model: Trained model pipeline
        sample_data: DataFrame with same features as training data
        
    Returns:
        predictions: 0 (benign) or 1 (attack)
        probabilities: Probability of being an attack
    """
    predictions = model.predict(sample_data)
    probabilities = model.predict_proba(sample_data)[:, 1]  # Probability of attack
    
    return predictions, probabilities


def demo_prediction():
    """
    Demo: Load a few samples from the training set and predict on them.
    """
    print("="*70)
    print("UNSW-NB15 Attack Detection - Inference Demo")
    print("="*70)
    
    # Load model
    model = load_model()
    if model is None:
        return
    
    # Load some samples from the dataset
    print("\nLoading test samples from dataset...")
    try:
        df = pd.read_csv('UNSW_NB15_training-set.csv', nrows=10)
        
        # Separate features and labels
        y_true = df['label']
        X = df.drop(columns=['label', 'id', 'attack_cat'], errors='ignore')
        
        print(f"✓ Loaded {len(X)} samples for testing")
        
        # Make predictions
        print("\nMaking predictions...")
        predictions, probabilities = predict_sample(model, X)
        
        # Display results
        print("\n" + "="*70)
        print("PREDICTION RESULTS")
        print("="*70)
        print(f"{'Sample':<8} {'True':<8} {'Predicted':<12} {'Probability':<12} {'Status':<10}")
        print("-"*70)
        
        for i in range(len(predictions)):
            true_label = 'Attack' if y_true.iloc[i] == 1 else 'Benign'
            pred_label = 'Attack' if predictions[i] == 1 else 'Benign'
            prob = probabilities[i]
            status = '✓ Correct' if y_true.iloc[i] == predictions[i] else '✗ Wrong'
            
            print(f"{i+1:<8} {true_label:<8} {pred_label:<12} {prob:<12.4f} {status:<10}")
        
        # Summary
        correct = sum(y_true == predictions)
        accuracy = correct / len(predictions) * 100
        print("-"*70)
        print(f"Accuracy on these samples: {correct}/{len(predictions)} ({accuracy:.1f}%)")
        print("="*70)
        
    except FileNotFoundError:
        print("ERROR: UNSW_NB15_training-set.csv not found")
        print("Place the dataset file in the current directory to run the demo.")
    except Exception as e:
        print(f"ERROR: {e}")


def predict_new_sample(model, features_dict):
    """
    Predict on a single new sample with feature dictionary.
    
    Example:
        features = {
            'dur': 0.121478,
            'proto': 'tcp',
            'service': '-',
            'state': 'FIN',
            'spkts': 6,
            'dpkts': 4,
            ...
        }
        result = predict_new_sample(model, features)
    """
    df = pd.DataFrame([features_dict])
    prediction, probability = predict_sample(model, df)
    
    return {
        'prediction': 'Attack' if prediction[0] == 1 else 'Benign',
        'attack_probability': probability[0],
        'confidence': max(probability[0], 1 - probability[0])
    }


if __name__ == '__main__':
    demo_prediction()
    
    print("\n" + "="*70)
    print("HOW TO USE THIS MODEL IN YOUR CODE")
    print("="*70)
    print("""
1. Load the model:
   import joblib
   model = joblib.load('trained_models/unsw_attack_detector.joblib')

2. Prepare your data as a DataFrame with the same features as training:
   import pandas as pd
   X_new = pd.DataFrame([{
       'dur': 0.5, 'proto': 'tcp', 'state': 'FIN',
       'spkts': 10, 'dpkts': 8, ...
   }])

3. Make predictions:
   predictions = model.predict(X_new)  # Returns 0 (benign) or 1 (attack)
   probabilities = model.predict_proba(X_new)[:, 1]  # Attack probability

4. Interpret results:
   if predictions[0] == 1:
       print(f"⚠️ ATTACK DETECTED! (confidence: {probabilities[0]:.2%})")
   else:
       print(f"✓ Benign traffic (confidence: {1-probabilities[0]:.2%})")
""")
    print("="*70)
