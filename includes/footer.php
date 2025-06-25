    <footer>
        <div class="logo">$-$quare $ecurity</div>
        <div class="team">
            <a href="#">Stuck Loop</a>
        </div>
    </footer>

    <script>
        const form = document.querySelector("form");
        const loader = document.getElementById("loader");

        form.addEventListener("submit", function () {
            loader.style.display = "block";
        });

        // Get dropdown and input elements
        const dropdown = document.getElementById("action");
        const hostInput = document.getElementById("hostInput");
        const domainInput = document.getElementById("domainInput");
        const xssInput = document.getElementById("xssInput");
        const t1 = document.getElementById("tooltip1");
        const t2 = document.getElementById("tooltip2");
        const t3 = document.getElementById("tooltip3");

        // Hide all inputs by default
        domainInput.style.display = "none";
        xssInput.style.display = "none";
        t2.style.display = "none";
        t3.style.display = "none";

        // Event listener to show/hide input fields based on selected action
        dropdown.addEventListener("change", function () {
            const selectedOption = dropdown.value;

            // Hide both input fields by default
            hostInput.style.display = "none";
            domainInput.style.display = "none";
            xssInput.style.display = "none";
            t1.style.display = "none";
            t2.style.display = "none";
            t3.style.display = "none";

            // Show the correct input field based on selected option
            if (selectedOption === "port_scan") {
                hostInput.style.display = "flex";
                t1.style.display = "flex";
            } else if (selectedOption === "wayback_sql_injection") {
                domainInput.style.display = "flex";
                t2.style.display = "flex";
            }
            else if (selectedOption === "check_xss") {
                xssInput.style.display = "flex";
                t3.style.display = "flex";
            }
        });

        document.getElementById("download-pdf").addEventListener("click", function () {
            var element = document.getElementById('outputbox');
            var clone = element.cloneNode(true);
            clone.style.backgroundColor = 'white';
            clone.style.color = 'black';
            clone.style.fontFamily = 'Poppins, sans-serif';

            var h2Tags = clone.getElementsByTagName('h2');
            for (var i = 0; i < h2Tags.length; i++) {
                h2Tags[i].style.color = 'black';
            }

            var opt = {
                margin: 1,
                padding: 10,
                filename: 'report.pdf',
                image: { type: 'jpeg', quality: 0.98 },
                html2canvas: { scale: 4 },
                jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' }
            };

            html2pdf().from(clone).set(opt).save();
        });
    </script>
</body>
</html>
