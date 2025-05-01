import re
import pandas as pd


def parse_task_file(md_path: str) -> pd.DataFrame:
    # Original parsing logic - handles the format with "### filename" and "- Line X: task"
    if md_path == "test_results.md":
        task_pattern = re.compile(r"^- Line (\d+): (.+)")
        filename_pattern = re.compile(r"^### (.+)")

        current_file = None
        tasks = []
        with open(md_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("### "):  # Match any file path header
                    match = filename_pattern.match(line)
                    if match:
                        current_file = match.group(1).strip()
                elif line.startswith("- Line"):
                    match = task_pattern.match(line)
                    if match and current_file:
                        line_number = int(match.group(1))
                        task_desc = match.group(2).strip()
                        tasks.append(
                            {
                                "filename": current_file,  # Using correct field name
                                "line": line_number,
                                "task": task_desc,
                                "status": "TODO",
                                # Optional fields (null in DB if omitted)
                                "tag": None,
                                "severity": None,
                                "metadata_json": None,
                            }
                        )
    # handles the table format in task_list.md
    else:
        tasks = []
        with open(md_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

            # Skip headers
            for i, line in enumerate(lines):
                if "|----|" in line:
                    # Start parsing from the line after the separator
                    data_lines = lines[i + 1 :]
                    break
            else:
                data_lines = []  # In case no separator is found

            for line in data_lines:
                line = line.strip()
                if line.startswith("|"):
                    # Parse table row: | ID | Filename | Line | Task | Status |
                    parts = line.split("|")
                    if len(parts) >= 6:  # account for empty strings at start/end
                        try:
                            # Skip the ID field (parts[1])
                            filename = parts[2].strip()
                            line_number = int(parts[3].strip())
                            task_desc = parts[4].strip()
                            status = parts[5].strip()

                            tasks.append(
                                {
                                    # "id" field removed to let database auto-assign
                                    "filename": filename,  # Using correct field name
                                    "line": line_number,
                                    "task": task_desc,
                                    "status": status,
                                    # Optional fields (null in DB if omitted)
                                    "tag": None,
                                    "severity": None,
                                    "metadata_json": None,
                                }
                            )
                        except ValueError:
                            # Skip rows that can't be properly parsed (like headers or separators)
                            continue

    df = pd.DataFrame(tasks)
    return df


def export_markdown(df: pd.DataFrame, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# Structured Task List\n\n")
        f.write("| ID | Filename | Line | Task | Status |\n")
        f.write("|----|----------|------|------|--------|\n")
        # Use index+1 as a display-only ID for the markdown file
        for idx, row in df.iterrows():
            f.write(
                f"| {idx+1} | {row['filename']} | {row['line']} | {row['task']} | {row['status']} |\n"  # Using correct field name
            )


def main():
    input_md = "test_results.md"
    output_md = "task_list.md"
    df = parse_task_file(input_md)
    export_markdown(df, output_md)
    print(f"Parsed {len(df)} tasks. Output saved to {output_md}.")


if __name__ == "__main__":
    main()
