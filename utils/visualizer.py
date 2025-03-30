import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

def visualize_data(csv_file):
    df = pd.read_csv(csv_file)
    sns.pairplot(df)
    plt.show()