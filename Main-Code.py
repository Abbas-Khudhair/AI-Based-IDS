import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import re


# Function to preprocess the data
def preprocess_data(file_path):
    try:
        # Load the CSV file
        data = pd.read_csv(file_path)

        # Select relevant features (for simplicity, this will depend on your dataset)
        features = ['Source Port', 'Destination Port', 'Protocol', 'Packet Length', 'Timestamp']
        target = 'Label'  # Assuming there is a "Label" column for classification

        # Ensure necessary columns are present
        for col in features + [target]:
            if col not in data.columns:
                raise ValueError(f"Missing required column: {col}")

        # Encode categorical features (e.g., Protocol)
        data['Protocol'] = data['Protocol'].astype('category').cat.codes

        # Preprocess the Timestamp column
        # Convert Timestamp to datetime
        data['Timestamp'] = pd.to_datetime(data['Timestamp'], errors='coerce')
        if data['Timestamp'].isna().any():
            raise ValueError("Invalid timestamp format detected.")

        # Extract features from Timestamp (e.g., hour and day)
        data['Hour'] = data['Timestamp'].dt.hour
        data['Day'] = data['Timestamp'].dt.day
        data['Month'] = data['Timestamp'].dt.month
        data['Year'] = data['Timestamp'].dt.year

        # Remove the original Timestamp column
        features.remove('Timestamp')
        features.extend(['Hour', 'Day', 'Month', 'Year'])

        # Handle missing values
        data = data.dropna()

        X = data[features]
        y = data[target]
        return X, y
    except Exception as e:
        print(f"Error during preprocessing: {e}")
        return None, None


# Function for deep packet inspection (regex-based simulation)
# Function for deep packet inspection (regex-based simulation)
def deep_packet_inspection(row):
    # Simulated DPI checks for suspicious patterns in specific fields (e.g., payload or text-like fields)
    suspicious_patterns = [
        r'password', r'admin', r'\\x[0-9a-fA-F]{2}',  # Fixed escape sequence
        r'sql', r'injection', r'select', r'from', r'where'  # SQL-like patterns
    ]

    # Combine all text-like fields into one string for inspection
    packet_str = ' '.join(map(str, row.values))  # Convert all row values to strings

    for pattern in suspicious_patterns:
        if re.search(pattern, packet_str, re.IGNORECASE):
            return 1  # Mark as suspicious
    return 0  # Mark as normal


# Function to train and evaluate the model
def train_and_evaluate(X, y):
    try:
        # Split the data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

        # Train a machine learning model (Random Forest in this case)
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)

        # Evaluate the model
        y_pred = model.predict(X_test)
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))

        print("Classification Report:")
        print(classification_report(y_test, y_pred))

        return model
    except Exception as e:
        print(f"Error during training: {e}")
        return None


# Format the numeric columns to remove trailing zeros
def format_numeric_columns(df):
    for col in df.select_dtypes(include=[np.float64]):
        df[col] = df[col].apply(lambda x: f'{x:g}')  # Format number to remove trailing zeros
    return df

# Main function to simulate the system
def main():
    csv_file_path = input("Enter the path to the CSV file: ")

    # Step 1: Preprocess the data
    X, y = preprocess_data(csv_file_path)
    if X is None or y is None:
        return

    # Step 2: Train the model
    model = train_and_evaluate(X, y)
    if model is None:
        return

    # Step 3: Inspect and analyze new packets
    print("Analyzing packets for suspicious behavior...")

    # Simulate loading new packets
    new_packets = X.sample(5)  # Replace with real packet data in production
    new_packets['Suspicious'] = new_packets.apply(lambda row: deep_packet_inspection(row), axis=1)

    # Ensure the 'Suspicious' column is excluded before making predictions
    predictions = model.predict(new_packets.drop(columns=['Suspicious']))
    new_packets['Prediction'] = predictions

    # Format the numeric columns to remove trailing zeros
    new_packets = format_numeric_columns(new_packets)

    print("Inspection Results:")
    print(new_packets)

if __name__ == "__main__":
    main()
