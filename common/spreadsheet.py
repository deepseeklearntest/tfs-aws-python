"""Write external strings as literal Excel text, including leading '=' values."""


def set_literal_cell(ws, row: int, column: int, value):
    cell = ws.cell(row=row, column=column, value=value)
    if isinstance(value, str):
        cell.data_type = 's'
    return cell


def append_literal_row(ws, values) -> None:
    values = list(values)
    ws.append(values)
    for column, value in enumerate(values, 1):
        if isinstance(value, str):
            ws.cell(ws.max_row, column).data_type = 's'
