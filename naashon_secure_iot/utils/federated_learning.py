"""
Federated Learning utilities for NaashonSecureIoT.
"""

import torch

class FederatedLearning:
    def __init__(self):
        pass

    def aggregate_models(self, models):
        """
        Aggregates models from edge devices using simple averaging.
        """
        if not models:
            return None

        # Get the weights of the first model
        aggregated_weights = models[0].state_dict()

        # Iterate through the remaining models and add their weights
        for model in models[1:]:
            for key in aggregated_weights.keys():
                aggregated_weights[key] += model.state_dict()[key]

        # Divide by the number of models to get the average weights
        for key in aggregated_weights.keys():
            aggregated_weights[key] /= len(models)

        # Load the aggregated weights into a new model
        aggregated_model = models[0]
        aggregated_model.load_state_dict(aggregated_weights)

        return aggregated_model

    def train_model(self, model, data, labels, epochs=10, lr=0.001):
        """
        Trains the model on edge devices.
        """
        model.train()
        optimizer = torch.optim.Adam(model.parameters(), lr=lr)
        criterion = torch.nn.BCELoss()

        for epoch in range(epochs):
            total_loss = 0
            for i, data_point in enumerate(data):
                input_tensor = torch.tensor(data_point, dtype=torch.float32)
                label = torch.tensor([labels[i]], dtype=torch.float32)

                optimizer.zero_grad()
                output = model(input_tensor)
                loss = criterion(output, label)
                loss.backward()
                optimizer.step()

                total_loss += loss.item()

            print(f"Epoch {epoch+1}/{epochs}, Loss: {total_loss/len(data):.4f}")

        model.eval()
        return model
