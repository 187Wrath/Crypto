import pandas as pd

def deflag_packets(input_file, output_file):
    """
    Removes the red-flagged status from packets in a dataset.

    Parameters:
        input_file (str): Path to the input CSV file containing packet data.
        output_file (str): Path to save the deflagged output CSV file.

    Assumptions:
        - The CSV file has a column named 'flag' with values 'red' for red-flagged packets.
        - The deflagged packets will have their 'flag' column set to 'none'.
    """
    try:
        # Load the dataset
        df = pd.read_csv(input_file)

        # Check if the 'flag' column exists
        if 'flag' not in df.columns:
            raise ValueError("The input file does not have a 'flag' column.")

        # Deflag packets flagged as 'red'
        red_flagged_count = df[df['flag'] == 'red'].shape[0]
        df.loc[df['flag'] == 'red', 'flag'] = 'none'

        # Save the updated dataset
        df.to_csv(output_file, index=False)

        print(f"Successfully deflagged {red_flagged_count} packets. Updated file saved to {output_file}.")
    except FileNotFoundError:
        print(f"Error: The file '{input_file}' was not found.")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Example usage
if __name__ == "__main__":
    input_csv = "packets.csv"  # Replace with your input file path
    output_csv = "deflagged_packets.csv"  # Replace with your output file path
    deflag_packets(input_csv, output_csv)
