from agent.agent import Agent
from computers import LocalPlaywrightComputer
from utils import create_response_azure


def main(user_input=None):
    with LocalPlaywrightComputer() as computer:
        # Create an agent that uses Azure OpenAI API instead of standard OpenAI API
        agent = Agent(computer=computer)
        
        # Override the run_full_turn method to use create_response_azure
        original_run_full_turn = agent.run_full_turn
        
        def azure_run_full_turn(input_items, print_steps=True, debug=False, show_images=False):
            agent.print_steps = print_steps
            agent.debug = debug
            agent.show_images = show_images
            new_items = []

            # Keep looping until we get a final response
            while new_items[-1].get("role") != "assistant" if new_items else True:
                agent.debug_print([input_items + new_items])

                # Use the Azure version instead of standard OpenAI API
                response = create_response_azure(
                    model=agent.model,
                    input=input_items + new_items,
                    tools=agent.tools,
                    truncation="auto",
                )
                agent.debug_print(response)

                if "output" not in response and agent.debug:
                    print(response)
                    raise ValueError("No output from model")
                else:
                    new_items += response["output"]
                    for item in response["output"]:
                        new_items += agent.handle_item(item)

            return new_items
        
        # Replace the standard method with our Azure-enabled version
        agent.run_full_turn = azure_run_full_turn
        
        items = []
        while True:
            user_input = input("> ")
            items.append({"role": "user", "content": user_input})
            output_items = agent.run_full_turn(items, debug=True, show_images=True)
            items += output_items


if __name__ == "__main__":
    main()