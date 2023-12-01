Here are few example cases how the control flow for type switch should look like(left) and what we get from builtin cfg package(right):
# **Category: Standalone SelectStmt**
**Example-1: Without default**
```
func foo(n interface{}) string {
	var msg string
	switch n.(type) {
	case int, float64:
		msg = "number"
	case string:
		msg = "text"
	}
	return msg
}
```
```mermaid
graph LR;
    A(msg string) --> B("n.(type)")
    B --> C(int)
    C --> |T|D(msg=&quotnumber&quot)
    C --> |F|E(float64)
    E --> |T|D
    E --> |F|F(string)
    F --> |T|H(msg = &quottext&quot)
    F --> |F|I(msg = &quotunknown&quot)
    I --> G(return msg)
```

**Example-2: With default**
```
func foo(n interface{}) string {
	var msg string
	switch n.(type) {
	case int, float64:
		msg = "number"
	case string:
		msg = "text"
	default:
		msg = "unknown"
	}
	return msg
}
```
```mermaid
graph LR;
    A(msg string) --> B("n.(type)")
    B --> C(int)
    C --> |true|D(msg=&quotnumber&quot)
    D --> G
    C --> |false|E(float64)
    E --> |true|D
    E --> |false|F(string)
    F --> |true|H(msg = &quottext&quot)
    H --> G(return msg)
    F --> |false|I(msg = &quotunknown&quot)
    I --> G
```
**Example-3: Empty Case Without default**
```
func foo(n interface{}) string {
	var msg string
	switch n.(type) {
	case int, float64:
	case string:
		msg = "text"
	}
	return msg
}
```
```mermaid
graph LR;
    A(msg string) --> B("n.(type)")
    B --> C(int)
    C --> |true|G
    C --> |false|E(float64)
    E --> |true|G
    E --> |false|F(string)
    F --> |true|H(msg = &quottext&quot)
    F --> |false|G
    H --> G(return msg)
```

**Example-4: Empty Case With default**
```
func foo(n interface{}) string {
	var msg string
	switch n.(type) {
	case int, float64:
	case string:
		msg = "text"
	default:
		msg = "unknown"
	}
	return msg
}
```
```mermaid
graph LR;
    A(msg string) --> B("n.(type)")
    B --> C(int)
    C --> |true|G
    C --> |false|E(float64)
    E --> |true|G
    E --> |false|F(string)
    F --> |true|H(msg = &quottext&quot)
    F --> |false|I(msg = &quotunknown&quot)
    I --> G
    H --> G(return msg)
```
**Example-5: Empty default**
```
func foo(n interface{}) string {
	var msg string
	switch n.(type) {
	case int, float64:
	case string:
		msg = "text"
	default:
	}
	return msg
}
```
```mermaid
graph LR;
    A(msg string) --> B("n.(type)")
    B --> C(int)
    C --> |true|G
    C --> |false|E(float64)
    E --> |true|G
    E --> |false|F(string)
    F --> |true|H(msg = &quottext&quot)
    F --> |false| G
    H --> G(return msg)
```
**Example-6: Only default**
```
func foo(n interface{}) string {
	var msg string
	switch n.(type) {
	default:
		msg = "unknown"
	}
	return msg
}
```
```mermaid
graph LR;
   A(msg string) --> B("n.(type)")
    B --> C(msg = &quotunknown&quot)
    C --> G(return msg)

```
# **Category: TypeSwitch inside RangeStmt**
**Example-7: Without default**
```
func foo(n interface{}) string {
	var msg []string
	for idx, val := range msg {
		switch n.(type) {
		case float64:
			msg[idx] = "int"
		case string:
			msg[idx] = "text"
	}
	return msg
}
```
```mermaid
graph LR;
    A(msg string) --> B(msg)
    B --> C(idx)
    C --> D(val)
    D --> E("n.(type)")
    E --> F(int)
    F --> |true|G("msg[idx] = &quotint&quot")
    F --> |false|H(string)
    G --> E
    G --> I(return msg)
    H --> |true|J("msg[idx] = &quottext&quot")
    H --> |false|E
    H --> |false|I
    J --> E
    J --> I
```
**Example - 8: With default**
```
func foo(n interface{}) string {
	var msg []string
	for idx, val := range msg {
		switch n.(type) {
		case int:
			msg[idx] = "int"
		case string:
			msg[idx] = "text"
		default:
			msg[idx] = "unknown"
	}
	return msg
}
```
```mermaid
graph LR;
    A(msg string) --> B(msg)
    B --> C(idx)
    C --> D(val)
    D --> E("n.(type)")
    E --> F(int)
    F --> |true|G("msg[idx] = &quotint&quot")
    F --> |false|H(string)
    G --> E
    G --> I(return msg)
    H --> |true|J("msg[idx] = &quottext&quot")
    H --> |false|E
    H --> |false|K("msg[idx] = &quotunknown&quot")
    K --> E
    K --> I
    J --> E
    J --> I
```
**Example - 9: Empty Case Without default**
```
func foo(n interface{}) string {
	var msg []string
	for idx, val := range msg {
		switch n.(type) {
		case int:
		case string:
			msg[idx] = "text"
	}
	return msg
}
```
```mermaid
graph LR;
    A(msg string) --> B(msg)
    B --> C(idx)
    C --> D(val)
    D --> E("n.(type)")
    E --> F(int)
    F --> |false|H(string)
    F --> |true|E
    F --> |true|I(return msg)
    H --> |true|J("msg[idx] = &quottext&quot")
    H --> |false|E
    H --> |false|I
    J --> E
    J --> I
```
**Example - 10: Empty Case With default**
```
func foo(n interface{}) string {
	var msg []string
	for idx, val := range msg {
		switch n.(type) {
		case int:
		case string:
			msg[idx] = "text"
		default:
			msg[idx] = "unknown"
	}
	return msg
}
```
```mermaid
graph LR;
   A(msg string) --> B(msg)
    B --> C(idx)
    C --> D(val)
    D --> E("n.(type)")
    E --> F(int)
    F --> |false|H(string)
    F --> |true|E
    F --> |true|I(return msg)
    H --> |true|J("msg[idx] = &quottext&quot")
    H --> |false|K("msg[idx] = &quotunknown&quot")
    J --> E
    J --> I
    K --> I
    K --> E
```
**Example - 11: Empty default**
```
func foo(n interface{}) string {
	var msg []string
	for idx, val := range msg {
		switch n.(type) {
		case int:
                        msg[idx] = "int"
		case string:
			msg[idx] = "text"
		default:
	}
	return msg
}
```
```mermaid
graph LR;
   A(msg string) --> B(msg)
    B --> C(idx)
    C --> D(val)
    D --> E("n.(type)")
    E --> F(int)
    F --> |false|H(string)
    F --> |true|G("msg[idx] = &quotint&quot")
    G --> E
    G --> I(return msg)
    H --> |true|J("msg[idx] = &quottext&quot")
    H --> |false|E
    H --> |false|I
    J --> E
    J --> I
```
**Example - 12: Only default**
```
func foo(n interface{}) string {
	var msg []string
	for idx, val := range msg {
		switch n.(type) {
		default:
                     msg[idx] = "unknown"
	}
	return msg
}
```
```mermaid
graph LR;
   A(msg string) --> B(msg)
    B --> C(idx)
    C --> D(val)
    D --> E("n.(type)")
    E --> F("msg[idx] = &quotunknwon&quot")
    F --> G(return msg)
    F --> E
```

case int, float :
    fmt

    .4 #kdfj
    int
    