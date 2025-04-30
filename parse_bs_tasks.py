import re
import pandas as pd


def parse_task_file(md_path: str) -> pd.DataFrame:
    task_pattern = re.compile(r"^- Line (\d+): (.+)")
    filename_pattern = re.compile(r"^### (.+)")

    current_file = None
    tasks = []
    task_id = 1

    with open(md_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("### src") or line.startswith("### tests"):
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
                            "id": task_id,  # Matches schema
                            "filename": current_file,
                            "line": line_number,
                            "task": task_desc,
                            "status": "TODO",
                            # Optional fields (null in DB if omitted)
                            "tag": None,
                            "severity": None,
                            "metadata_json": None,
                        }
                    )
                    task_id += 1

    df = pd.DataFrame(tasks)
    return df


def export_markdown(df: pd.DataFrame, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# Structured Task List\n\n")
        f.write("| ID | Filename | Line | Task | Status |\n")
        f.write("|----|----------|------|------|--------|\n")
        for _, row in df.iterrows():
            f.write(
                f"| {row['id']} | {row['filename']} | {row['line']} | {row['task']} | {row['status']} |\n"
            )


def main():
    input_md = "bs-test-results-full.md"
    output_md = "structured_task_list.md"
    df = parse_task_file(input_md)
    export_markdown(df, output_md)
    print(f"Parsed {len(df)} tasks. Output saved to {output_md}.")


if __name__ == "__main__":
    main()
